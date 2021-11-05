using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Numerics;
using System.Threading;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;

namespace crsa
{
    class CRsa
    {
        //Greatest Common Divisor
        private BigInteger gcd(BigInteger a, BigInteger b)
        {
            if (b == 0) return a;
            return gcd(b, a % b);
        }

        //Least Common Multiple
        private BigInteger lcm(BigInteger a, BigInteger b)
        {
            return BigInteger.Abs(a * b) / gcd(a, b);
        }

        //Simple string CRC
        private int PasswordCrc(string passwd)
        {
            int r = 0;

            if (!passwd.Any()) return 0xff;
            foreach (char c in passwd) r ^= c;
            return r & 0xff;
        }

        //Check if *value* is prime, by using parallel threads
        static bool IsPrime(BigInteger v)
        {
            if (v < 1) return false;
            else
            {
                if (v <= 3) return true;
                else if (v % 2 == 0 || v % 3 == 0) return false;
                else 
                {
                    BigInteger i = 5;

                    while (i * i <= v)
                    {
                        if (v % i == 0 || (v % (i + 2) == 0)) return false;
                        i += 6;
                    }
                    return true;
                }
            }
        }

        private int NextPrimeNumber(Random rnd, ref BigInteger bi)
        {
            byte[] pBytes = new byte[16];

            rnd.NextBytes(pBytes);
            bi = new BigInteger(pBytes);
            if (bi < 2) bi = 2;
            while (!IsPrime(bi)) 
                bi++; //Find prime
            return bi.ToString().Length;
        }

        private BigInteger GetEncryptionExponent(BigInteger bi)
        {
            BigInteger e = 2;

            while (e < bi)
            {
                if (gcd(e, bi) != 1) e++;
                else break;
            }
            return e;
        }

        private BigInteger GetDecryptionExponent(BigInteger phi, BigInteger e)
        {
            /*Modular multiplicative inverse*/
            if (phi > 0)
            {
                e %= phi;
                for (BigInteger x = 1; x < phi; x++)
                    if (e * x % phi == 1)
                        return x;
            }
            return 1;
        }

        public void GenerateKeys(out BigInteger pubKey, out BigInteger privKey)
        {
            BigInteger P = 2;
            BigInteger Q = 2;
            BigInteger phi;
            BigInteger e;
            BigInteger d;
            BigInteger n;
            Random rnd = new Random((int) DateTime.Now.Ticks);
            int l1;
            long pMark;
            MemoryStream s = new MemoryStream();
            BinaryFormatter b = new BinaryFormatter();

            l1 = NextPrimeNumber(rnd, ref P); //Get first prime number
            for (int i = 0; NextPrimeNumber(rnd, ref Q) == l1 && i < 10000; ) ++i; //Choose a different digits size prime number
            n = P * Q; //Modulo value
            phi = lcm(P - 1, Q - 1); //Totient
            e = GetEncryptionExponent(phi); //Find public key (e), exponent
            d = GetDecryptionExponent(phi, e); //Find private key (d), exponent
            /*Create public key byte array*/
            b.Serialize(s, n);
            pMark = s.Position; //Save serialized N size
            b.Serialize(s, e);
            pubKey = new BigInteger(s.ToArray());
            s.Position = pMark;
            b.Serialize(s, d);
            privKey = new BigInteger(s.ToArray());
        }

        private byte[] Padding(string plain)
        {
            byte[] r, fill;
            Random rnd = new Random((int)DateTime.Now.Ticks);
            int missing = 8 - plain.Length % 8; //Encryption and decryption is set to 8 bytes number (UINT64)

            if (plain == null || plain.Length == 0) return null;
            r = Encoding.UTF8.GetBytes(plain);
            if (missing > 0)
            {
                fill = new byte[missing];
                rnd.NextBytes(fill);
                fill = fill.Select(b => (byte) (b & 0x1f)).ToArray(); //Limit ramdom array to non printable characters
                r = r.Concat(fill).ToArray();                     //Thus it'll be easier to separate in decrypted stream
            }
            return r;
        }

        private void GetNED(BigInteger key, out BigInteger n, out BigInteger ed)
        {
            MemoryStream s = new MemoryStream(key.ToByteArray());
            BinaryFormatter b = new BinaryFormatter();

            n = (BigInteger)b.Deserialize(s); //Modulo
            ed = (BigInteger)b.Deserialize(s); //Exponent
        }

        public byte[] Encrypt(string plain, BigInteger pubKey)
        {
            byte[] r = null, p;
                        
            if (!plain.Any()) throw new ArgumentException("No data to encode");
            if (pubKey < 2) throw new ArgumentException("Invalid key value");
            GetNED(pubKey, out BigInteger n, out BigInteger e);
            p = Padding(plain);
            if (p != null)
            {
                var arr = plain.Select(b => BigInteger.Pow(b, (int)e) % n);
                MemoryStream ms = new MemoryStream();
                BinaryFormatter bf = new BinaryFormatter();

                foreach (BigInteger bi in arr) bf.Serialize(ms, bi);
                r = ms.ToArray();
            }
            return r;
        }

        public string Decrypt(byte[] encd, BigInteger privKey)
        {
            byte[] r = null, p;

            if (!encd.Any()) throw new ArgumentException("No data to decode");
            if (privKey < 2) throw new ArgumentException("Invalid key value");
            GetNED(privKey, out BigInteger n, out BigInteger d);
            if (encd != null)
            {
                MemoryStream ms = new MemoryStream(encd);
                BinaryFormatter b = new BinaryFormatter();
                BigInteger[] encbil = new BigInteger[0];

                while (ms.Position < encd.Length)
                    encbil.Append((BigInteger)b.Deserialize(ms));
                if (encbil.Any())
                {
                    r = encbil.Select(bi => (byte)(BigInteger.Pow(bi, (int)d) % n)) //Decrypt every big-integer
                        .Where(bt => bt >= 0x20) //Remove padding
                        .ToArray(); //Get array
                    return Encoding.UTF8.GetString(r);
                }
            }
            return null;
        }
    }
}
