# ManualMap (DLL Manual Mapper)

ManualMap is a lightweight DLL manual mapper that loads a PE image into a remote process without using `LoadLibrary`.  
The injector performs full PE image mapping in memory, resolves imports, applies relocations, initializes TLS, and finally executes the mapped module.

Execution of the mapped DLL is performed by creating a remote thread that runs a small shellcode stub.  
This stub manually invokes the module's `DllMain` with the proper parameters (`DLL_PROCESS_ATTACH`).

---

## 🚀 Features

- Full manual PE image mapping (no LoadLibrary)
- Import table resolution
- Relocation processing
- Shellcode stub that calls `DllMain`
- Executed via `CreateRemoteThread`
- Uses WinDeepMem library for low-level memory operations (read/write/allocate/protect/etc.)


## TODO
- TLS callback initialization
- Thread Hiajck
- Delete PEheaders after loading dll

## 📌 Usage Example

```csharp
 var tarProc = Process.GetProcessesByName("notepad").First();
 string pathToDll = @"PathToDll";

 Mapper mapper = new Mapper(tarProc, pathToDll);
 mapper.InjectImage();
