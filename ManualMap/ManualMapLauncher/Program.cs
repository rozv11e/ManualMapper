using ManualMap;
using System.Diagnostics;

namespace ManualMapLauncher
{
    class Program
    {
        public static void Main(string[] args)
        {
            var tarProc = Process.GetProcessesByName("notepad").First();
            string pathToDll = @"I:\Desktop\Tools\Dumpers\WowRetail-Dumper\x64\Release\Dumper.dll";

            Mapper mapper = new Mapper(tarProc, pathToDll);
            mapper.InjectImage();

            Console.ReadKey();
        }
    }
}