using System;
using System.Numerics;

namespace crsa
{
    class Program
    {

        static void Main(string[] args)
        {
            CRsa rsa = new CRsa();

            rsa.GenerateKeys(out BigInteger pubKey, out BigInteger privKey);

            Console.WriteLine("Pub = {0}\nPriv{1}", pubKey, privKey);
            Console.ReadKey();
        }
    }
}
