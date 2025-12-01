using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using WinDeepMem;
using WinDeepMem.Imports;
using WinDeepMem.Imports.Structures;
using static WinDeepMem.Imports.WinApi;

namespace ManualMap
{
    public class Mapper
    {
        private readonly Process _process;
        private readonly Memory mem;
        private readonly PEReader peReader;
        private readonly string _pathToDll;

        private PEParser peParser;
        public Mapper(Process process, string pathToDll)
        {
            _process = process;
            _pathToDll = pathToDll;
            mem = new Memory(process);
            peReader = new PEReader(_process);
        }

        private Dictionary<string, ulong> LinkedModules = new Dictionary<string, ulong>();
        private Dictionary<string, ulong> MappedModules = new Dictionary<string, ulong>();

        public bool InjectImage()
        {
            MappedModules.Clear();
            LinkedModules.Clear();

            var linkedModules = peReader.GetLoadedModules();
            foreach (var m in linkedModules)
            {
                var mName = peReader.ReadUnicodeString(m.BaseDllName);
                LinkedModules.Add(mName.ToLower(), (ulong)m.DllBase);
            }

            if (string.IsNullOrEmpty(_pathToDll))
            {
                Console.WriteLine("Dll not found");
                return false;
            }
            var rawImage = File.ReadAllBytes(_pathToDll);
            var hModule = MapImage(rawImage);

            // EXECUTE DLL
            CallEntrypoint(rawImage, (ulong)hModule); 
            //HijackMainThread((ulong)hModule, entryPoint);

            return true;
        }

        private nint MapImage(byte[] rawImage)
        {
            peParser = new PEParser(rawImage);

            // Get headers
            var dosHeader = peParser.DosHeader;
            var ntHeaders = peParser.NtHeaders;
            var optionalHeader = ntHeaders.OptionalHeader;
            var fileHeader = ntHeaders.FileHeader;

            var imageBase = optionalHeader.ImageBase;
            var entryPoint = optionalHeader.AddressOfEntryPoint;
            var remoteSize = optionalHeader.SizeOfImage;

            // Create buffer for alloc
            var buffer = new byte[remoteSize];

            // Move headers to buffer
            Array.Copy(rawImage, buffer, optionalHeader.SizeOfHeaders);

            // Print - MZ
            var mz = new byte[2];
            Array.Copy(buffer, mz, 2);
            Console.WriteLine(Encoding.UTF8.GetString(mz));

            if (Encoding.UTF8.GetString(mz) != "MZ")
            {
                Console.WriteLine("[Error] Not MZ");
                return nint.Zero;
            }

            int sectionHeadersOffset = dosHeader.e_lfanew
                                       + 4
                                       + 20
                                       + ntHeaders.FileHeader.SizeOfOptionalHeader;

            // Move sections
            for (int i = 0; i < peParser.NumberOfSections; i++)
            {
                var offset = sectionHeadersOffset + i * 40;
                var section = peParser.ReadStruct<IMAGE_SECTION_HEADER>(rawImage, offset);

                // Print: Name, VirtualAddress, VirtualSize, PointerToRawData, SizeOfRawData
                Console.WriteLine(section.SectionName);
                // memory:
                Console.WriteLine(section.VirtualAddress.ToString("X"));
                Console.WriteLine(section.VirtualSize.ToString("X"));
                // file:
                Console.WriteLine(section.PointerToRawData.ToString("X"));
                Console.WriteLine(section.SizeOfRawData.ToString("X"));
                Console.WriteLine();

                Array.Copy(
                    rawImage, // From
                    section.PointerToRawData, // offset in file
                    buffer, // To
                    section.VirtualAddress, // offset in memory
                    section.SizeOfRawData); // size of bytes to copy
            }

            // Allocate buffer in memory where will be mapped our dll
            var allocatedBase = mem.AllocateMemory((uint)buffer.Length);
            Console.WriteLine("Allocated memory: 0x" + allocatedBase.ToString("X"));
            mem.WriteBytes(allocatedBase, buffer);
            // Check alloc
            var dllBytes = mem.ReadBytes(allocatedBase, (uint)buffer.Length);
            //Console.WriteLine("BytesWrited: " + BitConverter.ToString(dllBytes));

            Console.WriteLine("-----FixRelocations------");
            FixRelocations(allocatedBase, peParser);
            Console.WriteLine("------FixIAT-----");
            FixIAT(allocatedBase);

            return allocatedBase;
        }
        private void FixRelocations(nint imageBase, PEParser peParser)
        {
            IMAGE_DATA_DIRECTORY relocs = peParser.GetDirectory(5);
            Console.WriteLine(relocs.VirtualAddress.ToString("X"));
            Console.WriteLine(relocs.Size.ToString("X"));

            var delta = imageBase - (nint)peParser.NtHeaders.OptionalHeader.ImageBase;
            Console.WriteLine($"Delta: 0x{delta:X}");

            var currentBlock = imageBase + relocs.VirtualAddress;

            Console.WriteLine("Blocks:");

            while (true)
            {
                var block = mem.ReadStruct<IMAGE_BASE_RELOCATION>((nint)currentBlock);
                if (block.SizeOfBlock == 0) break;

                Console.WriteLine($"RVA: 0x{block.VirtualAddress:X}");
                Console.WriteLine($"Size: {block.SizeOfBlock:X}");

                var count = (block.SizeOfBlock - 8) / 2;
                var entry = currentBlock + 8;

                for (int i = 0; i < count; i++)
                {
                    ushort typeOffset = mem.ReadUShort((nint)entry + i * 2);

                    int type = typeOffset >> 12;
                    int offset = typeOffset & 0xFFF;

                    // Пропускаем только IMAGE_REL_BASED_ABSOLUTE (тип 0)
                    if (type == 0) continue;

                    var patchAddr = imageBase + block.VirtualAddress + offset;

                    if (type == 0x3) // IMAGE_REL_BASED_HIGHLOW (32-bit)
                    {
                        var value = mem.ReadInt32((nint)patchAddr);
                        mem.Write<int>((nint)patchAddr, (int)(value + delta));
                    }
                    else if (type == 0xA) // IMAGE_REL_BASED_DIR64 (64-bit) ← ЭТО ДЛЯ X64!
                    {
                        var value = mem.ReadInt64((nint)patchAddr);
                        mem.Write<long>((nint)patchAddr, value + (long)delta);
                    }
                }

                currentBlock += block.SizeOfBlock;
            }
        }
        private bool FixIAT(nint imageBase)
        {
            var importDir = peParser.GetDirectory(1);
            if (importDir.Size == 0) return true;

            var descriptorAddr = imageBase + importDir.VirtualAddress;

            // Iterate through all the descriptors
            while (true)
            {
                var desc = mem.ReadStruct<IMAGE_IMPORT_DESCRIPTOR>((nint)descriptorAddr);
                if (desc.Name == 0)
                    break;

                var libName = mem.ReadString((nint)(imageBase + desc.Name));
                Console.WriteLine(libName);

                var hModule = LoadLibrary(libName);
                if (hModule == nint.Zero)
                {
                    Console.WriteLine($"[Error] Failed to load {libName}");
                    descriptorAddr += (uint)Marshal.SizeOf<IMAGE_IMPORT_DESCRIPTOR>();
                    continue;
                }

                var realName = GetModuleBaseName(Process.GetCurrentProcess().Handle, hModule);
                if (!string.IsNullOrEmpty(realName))
                {
                    libName = realName.ToLower();
                    Console.WriteLine($"  Resolved to: {libName}");
                }


                ulong remoteBase = 0;

                if (MappedModules.ContainsKey(libName.ToLower()))
                {
                    MappedModules.TryGetValue(libName.ToLower(), out remoteBase);
                    Console.WriteLine($"Found module in mapped modules: 0x{remoteBase:X}");
                }
                else if (LinkedModules.ContainsKey(libName.ToLower()))
                {
                    LinkedModules.TryGetValue(libName.ToLower(), out remoteBase);
                    Console.WriteLine($"Found module in target process: 0x{remoteBase:X}");
                }
                else
                {
                    Console.WriteLine("Module not found, mapping..");
                    var dllPath = FindDll(libName);

                    if (string.IsNullOrEmpty(dllPath))
                    {
                        Console.WriteLine("[Error] Dll not found on disk");
                        FreeLibrary(hModule);
                        descriptorAddr += (uint)Marshal.SizeOf<IMAGE_IMPORT_DESCRIPTOR>();
                        continue;
                    }

                    var rawBytes = File.ReadAllBytes(dllPath);
                    var mappedBase = MapImage(rawBytes);

                    MappedModules[libName.ToLower()] = (ulong)mappedBase;
                    remoteBase = (ulong)mappedBase;
                    Console.WriteLine($"Mapped at: 0x{remoteBase:X}");
                }

                // Fix funcs

                var origThunk = imageBase + desc.OriginalFirstThunk;
                var firstThunk = imageBase + desc.FirstThunk;

                while (true)
                {
                    ulong thunkData = peParser.Is32Bit
                        ? mem.ReadUInt32((nint)origThunk)
                        : mem.ReadUInt64((nint)origThunk);

                    if (thunkData == 0)
                        break;

                    IntPtr fnPtr;
                    bool isOrdinal = (thunkData & (peParser.Is32Bit ? 0x80000000 : 0x8000000000000000)) != 0;

                    if (isOrdinal)
                    {
                        ushort ordinal = (ushort)(thunkData & 0xFFFF);
                        fnPtr = GetProcAddressOrdinal(hModule, (IntPtr)ordinal);
                        Console.WriteLine($"    Ordinal #{ordinal}");
                    }
                    else
                    {
                        var nameAddr = imageBase + (nint)thunkData + 2;
                        var fnName = mem.ReadString(nameAddr);
                        fnPtr = GetProcAddress(hModule, fnName);
                        Console.WriteLine($"    {fnName}");
                    }

                    if (fnPtr == IntPtr.Zero)
                    {
                        Console.WriteLine($"      [Error] Function not found!");
                        origThunk += peParser.PtrSize;
                        firstThunk += peParser.PtrSize;
                        continue;
                    }

                    ulong rva = (ulong)fnPtr - (ulong)hModule;
                    ulong finalAddr = remoteBase + rva;
                    // ulong finalAddr = (ulong)fnPtr;

                    Console.WriteLine($"      RVA: 0x{rva:X} -> Final: 0x{finalAddr:X}");

                    if (finalAddr == 0)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine($"      [CRITICAL] NULL function address!");
                        Console.ForegroundColor = ConsoleColor.White;
                        continue;
                    }

                    var thunkValue = mem.ReadULong((nint)firstThunk);
                    Console.WriteLine($"BEFORE: firstThunk: 0x{thunkValue:X}");

                    // Write to IAT
                    if (peParser.Is32Bit)
                        mem.Write<uint>((nint)firstThunk, (uint)finalAddr);
                    else
                        mem.Write<ulong>((nint)firstThunk, finalAddr);

                    thunkValue = mem.ReadULong((nint)firstThunk);
                    Console.WriteLine($"AFTER: thunkValue: 0x{thunkValue:X}");

                    origThunk += peParser.PtrSize;
                    firstThunk += peParser.PtrSize;
                }

                FreeLibrary(hModule);
                descriptorAddr += (uint)Marshal.SizeOf<IMAGE_IMPORT_DESCRIPTOR>(); // just add offset (size of struct) to descriptorAddr
            }

            return true;
        }

        public static string GetModuleBaseName(IntPtr hProcess, IntPtr hModule)
        {
            var sb = new StringBuilder(260);
            WinApi.GetModuleBaseName(hProcess, hModule, sb, (uint)sb.Capacity);
            return sb.ToString();
        }

        // Search deps in sysyem folders or in current folder
        private string FindDll(string libName)
        {
            string[] searchPaths =
            {
                Directory.GetCurrentDirectory(), // Current directory
                Environment.SystemDirectory, // System32
                Environment.GetFolderPath(Environment.SpecialFolder.System), // System32
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64"), // SysWOW64
            };

            foreach (var path in searchPaths)
            {
                try
                {
                    var fullPath = Path.Combine(path, libName);
                    if (File.Exists(fullPath))
                        return fullPath;

                }
                catch (Exception ex)
                {
                    Console.WriteLine("" + ex.Message);
                }
            }

            return string.Empty;
        }

        private bool CallEntrypoint(byte[] rawImage, ulong hModule)
        {
            Console.WriteLine("---EXECUTION----");
            peParser = new PEParser(rawImage);
            var optionalHeader = peParser.NtHeaders.OptionalHeader;

            ulong entryPoint = hModule + optionalHeader.AddressOfEntryPoint;

            if (optionalHeader.AddressOfEntryPoint == 0)
            {
                Console.WriteLine("[Error] Invalid entrypoint");
                return false;
            }

            Console.WriteLine($"[DEBUG] hModule: 0x{hModule:X}");
            Console.WriteLine($"[DEBUG] EntryPoint RVA: 0x{optionalHeader.AddressOfEntryPoint:X}");
            Console.WriteLine($"[DEBUG] Full EntryPoint: 0x{entryPoint:X}");

            // ПРОВЕРКА: Читаем первые байты EntryPoint
            var entryBytes = mem.ReadBytes((nint)entryPoint, 16);
            Console.WriteLine($"[DEBUG] EntryPoint bytes: {BitConverter.ToString(entryBytes)}");

            nint cave = mem.AllocateMemory(0x100);
            Console.WriteLine($"[DEBUG] Cave allocated at: 0x{cave:X}");

            var shellcode = BuildShellcode(hModule, entryPoint);
            mem.WriteBytes(cave, shellcode);

            var asmBytes = mem.ReadBytes(cave, 0x100);
            Console.WriteLine($"[DEBUG] Shellcode: {BitConverter.ToString(asmBytes).Substring(0, 100)}...");

            Console.WriteLine("[DEBUG] Creating remote thread...");
            Thread.Sleep(500);

            var hThread = CreateRemoteThread(_process.Handle, IntPtr.Zero, 0, cave, IntPtr.Zero, 0, out _);

            if (hThread == IntPtr.Zero)
            {
                Console.WriteLine($"[ERROR] CreateRemoteThread failed! Error: {Marshal.GetLastWin32Error()}");
                return false;
            }

            Console.WriteLine($"[DEBUG] Thread created: 0x{hThread:X}");

            // Ждём завершения
            WaitForSingleObject(hThread, 5000); // 5 секунд таймаут

            uint exitCode = 0;
            GetExitCodeThread(hThread, out exitCode);
            Console.WriteLine($"[DEBUG] Thread exit code: 0x{exitCode:X}");


            CloseHandle(hThread);

            return true;
        }
        private byte[] BuildShellcode(ulong hModule, ulong entryPoint)
        {
            List<byte> sc = new();

            void QWORD(ulong v) => sc.AddRange(BitConverter.GetBytes(v));

            // sub rsp, 0x38
            sc.AddRange(new byte[] { 0x48, 0x83, 0xEC, 0x38 });

            // mov rcx, hModule
            sc.Add(0x48); sc.Add(0xB9); QWORD(hModule);

            // mov rdx, 1
            sc.AddRange(new byte[] { 0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00 });

            // xor r8, r8
            sc.AddRange(new byte[] { 0x4D, 0x31, 0xC0 });

            // mov rax, entryPoint
            sc.Add(0x48); sc.Add(0xB8); QWORD(entryPoint);

            // call rax
            sc.AddRange(new byte[] { 0xFF, 0xD0 });

            // add rsp, 0x38
            sc.AddRange(new byte[] { 0x48, 0x83, 0xC4, 0x38 });

            // ret
            sc.Add(0xC3);

            return sc.ToArray();
        }
    }
}
