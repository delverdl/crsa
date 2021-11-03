using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Numerics;
using System.Threading;

namespace crsa
{
    class CRsa
    {
        private BigInteger gcd(BigInteger a, BigInteger b)
        {
            if (b == 0) return a;
            return gcd(b, a % b);
        }

        private static int PasswordCrc(string passwd)
        {
            int r = 0;

            if (!passwd.Any()) return 0xff;
            foreach (char c in passwd)
            {
                r ^= c;
            }
            return r & 0xff;
        }

        public static BigInteger IntegerSquareRoot(BigInteger value)
        {
            if (value > 0)
            {
                int bitLength = value.ToByteArray().Length * 8;
                BigInteger root = BigInteger.One << (bitLength / 2);

                while (!IsSquareRoot(value, root))
                {
                    root += value / root;
                    root /= 2;
                }
                return root;
            }
            else return 0;
        }

        private static Boolean IsSquareRoot(BigInteger n, BigInteger root)
        {
            BigInteger lowerBound = root * root;
            BigInteger upperBound = (root + 1) * (root + 1);

            return (n >= lowerBound && n < upperBound);
        }

        static bool IsPrime(BigInteger value)
        {
            if (value < 3) return value == 2;
            else
            {
                if (value % 2 == 0) return false;
                else if (value == 5) return true;
                else if (value % 5 == 0) return false;
                else
                {
                    AutoResetEvent success = new AutoResetEvent(false);
                    AutoResetEvent failure = new AutoResetEvent(false);
                    AutoResetEvent onesSucceeded = new AutoResetEvent(false);
                    AutoResetEvent threesSucceeded = new AutoResetEvent(false);
                    AutoResetEvent sevensSucceeded = new AutoResetEvent(false);
                    AutoResetEvent ninesSucceeded = new AutoResetEvent(false);
                    BigInteger squareRootedValue = IntegerSquareRoot(value);
                    Thread ones = new Thread(() => {
                        for (BigInteger i = 11; i <= squareRootedValue; i += 10) if (value % i == 0) failure.Set();
                        onesSucceeded.Set();
                    });

                    ones.Start();

                    Thread threes = new Thread(() => {
                        for (BigInteger i = 3; i <= squareRootedValue; i += 10) if (value % i == 0) failure.Set();
                        threesSucceeded.Set();
                    });

                    threes.Start();

                    Thread sevens = new Thread(() => {
                        for (BigInteger i = 7; i <= squareRootedValue; i += 10) if (value % i == 0) failure.Set();
                        sevensSucceeded.Set();
                    });

                    sevens.Start();

                    Thread nines = new Thread(() => {
                        for (BigInteger i = 9; i <= squareRootedValue; i += 10) if (value % i == 0) failure.Set();
                        ninesSucceeded.Set();
                    });

                    nines.Start();
                    Thread successWaiter = new Thread(() => {
                        AutoResetEvent.WaitAll(new WaitHandle[] { onesSucceeded, threesSucceeded, sevensSucceeded,
                            ninesSucceeded });
                        success.Set();
                    });
                    successWaiter.Start();

                    int result = AutoResetEvent.WaitAny(new WaitHandle[] { success, failure });

                    try { successWaiter.Abort(); } catch { }
                    try { ones.Abort(); } catch { }
                    try { threes.Abort(); } catch { }
                    try { sevens.Abort(); } catch { }
                    try { nines.Abort(); } catch { }
                    if (result == 1) return false;
                    else return true;
                }
            }
        }

        private void NextPrimeNumber(Random rnd, out BigInteger bi)
        {
            byte[] pBytes = new byte[16];

            rnd.NextBytes(pBytes);
            bi = new BigInteger(pBytes);
            if (bi < 2) bi = 2;
            while (!IsPrime(bi)) bi++; //Find prime
        }

        public void GenerateKeys(out BigInteger pubKey, out BigInteger privKey, string passwd)
        {
            BigInteger phi;
            BigInteger e;
            BigInteger d;
            BigInteger n;
            BigInteger k = PasswordCrc(passwd);
            byte[] pBytes = new byte[16];
            Random rnd = new Random((int) DateTime.Now.Ticks);
            byte blen;
            List<byte> bt;

            NextPrimeNumber(rnd, out BigInteger P);
            NextPrimeNumber(rnd, out BigInteger Q);

            n = P * Q; //Encription/Decription modular
            phi = (P - 1) * (Q - 1); //Totient
            //Find public key (e), exponent
            e = 2;
            while (e < phi)
            {
                if (gcd(e, phi) != 1) e++;
                else break;
                if (e > 254) break;
            }
            //Find private key (d), exponent
            d = (k * phi + 1) / e;

            //To encript you need et = (msg ^ e) % 
            pBytes = n.ToByteArray();
            bt = new List<byte>(); 
            blen = (byte)pBytes.Length;
            bt.Add(blen);
            bt.Add(1);
            if (blen < 16) bt.AddRange(Enumerable.Repeat<byte>(0, 16 - blen));
            bt.AddRange(pBytes);
            bt.Add((byte)e);
            pubKey = new BigInteger(bt.ToArray());

            privKey = d;
        }

        public string Encrypt(string plain, BigInteger pubKey)
        {
            string s = "";
            byte[] ba = pubKey.ToByteArray();

            if (!plain.Any()) throw new ArgumentException("No data to encode");
            if (pubKey < 2) throw new ArgumentException("Invalid key value");
            if (ba.Length > 64) throw new ArgumentException("Key is to long");

            return s;
        }
    }
}
