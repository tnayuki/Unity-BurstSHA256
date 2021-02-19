using UnityEngine;
using Unity.Burst;
using Unity.Collections;
using Unity.Jobs;
using Stopwatch = System.Diagnostics.Stopwatch;
using File = System.IO.File;
using TimeSpan = System.TimeSpan;

public class SHA256FromFileBehaviour : MonoBehaviour {
	[BurstCompile]
    unsafe struct SHA256 {
        static void DBL_INT_ADD(ref uint a, ref uint b, uint c)
        {
            if (a > 0xffffffff - c) ++b; a += c;
        }

        static uint ROTLEFT(uint a, byte b)
        {
            return ((a << b) | (a >> (32 - b)));
        }

        static uint ROTRIGHT(uint a, byte b)
        {
            return (((a) >> (b)) | ((a) << (32 - (b))));
        }

        static uint CH(uint x, uint y, uint z)
        {
            return (((x) & (y)) ^ (~(x) & (z)));
        }

        static uint MAJ(uint x, uint y, uint z)
        {
            return (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)));
        }

        static uint EP0(uint x)
        {
            return (ROTRIGHT(x, 2) ^ ROTRIGHT(x, 13) ^ ROTRIGHT(x, 22));
        }

        static uint EP1(uint x)
        {
            return (ROTRIGHT(x, 6) ^ ROTRIGHT(x, 11) ^ ROTRIGHT(x, 25));
        }

        static uint SIG0(uint x)
        {
            return (ROTRIGHT(x, 7) ^ ROTRIGHT(x, 18) ^ ((x) >> 3));
        }

        static uint SIG1(uint x)
        {
            return (ROTRIGHT(x, 17) ^ ROTRIGHT(x, 19) ^ ((x) >> 10));
        }

        public fixed byte data[64];
        public int datalen;
        public ulong bitlen;

        public fixed uint state[8];

        static readonly uint[] k = {
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
        };

        private static void Transform(SHA256 *instance)
        {
            uint a, b, c, d, e, f, g, h, i, j, t1, t2;
            var m = stackalloc uint[64];

            for (i = 0, j = 0; i < 16; ++i, j += 4)
                m[i] = (uint)((instance->data[(int)j] << 24) | (instance->data[(int)j + 1] << 16) | (instance->data[(int)j + 2] << 8) | (instance->data[(int)j + 3]));

            for (; i < 64; ++i)
                m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

            a = instance->state[0];
            b = instance->state[1];
            c = instance->state[2];
            d = instance->state[3];
            e = instance->state[4];
            f = instance->state[5];
            g = instance->state[6];
            h = instance->state[7];

            for (i = 0; i < 64; ++i)
            {
                t1 = h + EP1(e) + CH(e, f, g) + k[i] + m[i];
                t2 = EP0(a) + MAJ(a, b, c);
                h = g;
                g = f;
                f = e;
                e = d + t1;
                d = c;
                c = b;
                b = a;
                a = t1 + t2;
            }

            instance->state[0] += a;
            instance->state[1] += b;
            instance->state[2] += c;
            instance->state[3] += d;
            instance->state[4] += e;
            instance->state[5] += f;
            instance->state[6] += g;
            instance->state[7] += h;
        }

        public static void Initialize(SHA256 *instance)
        {
            instance->state[0] = 0x6a09e667;
            instance->state[1] = 0xbb67ae85;
            instance->state[2] = 0x3c6ef372;
            instance->state[3] = 0xa54ff53a;
            instance->state[4] = 0x510e527f;
            instance->state[5] = 0x9b05688c;
            instance->state[6] = 0x1f83d9ab;
            instance->state[7] = 0x5be0cd19;
        }

    	[BurstCompile]
        public static void Update(SHA256 *instance, byte *buffer, int sz)
        {
            for (int i = 0; i < sz; ++i)
            {
                instance->data[instance->datalen] = buffer[i];
                instance->datalen++;

                if (instance->datalen == 64)
                {
                    Transform(instance);
                    instance->bitlen += 512;
                    instance->datalen = 0;
                }
            }
        }

        public static void Final(SHA256 *instance, NativeArray<byte> hash)
        {
            int i = instance->datalen;

            if (instance->datalen < 56)
            {
                instance->data[i++] = 0x80;

                while (i < 56)
                    instance->data[i++] = 0x00;
            }
            else
            {
                instance->data[i++] = 0x80;

                while (i < 64)
                    instance->data[i++] = 0x00;

                Transform(instance);
            }

            instance->bitlen += (ulong)instance->datalen * 8;
            instance->data[63] = (byte)(instance->bitlen);
            instance->data[62] = (byte)(instance->bitlen >> 8);
            instance->data[61] = (byte)(instance->bitlen >> 16);
            instance->data[60] = (byte)(instance->bitlen >> 24);
            instance->data[59] = (byte)(instance->bitlen >> 32);
            instance->data[58] = (byte)(instance->bitlen >> 40);
            instance->data[57] = (byte)(instance->bitlen >> 48);
            instance->data[56] = (byte)(instance->bitlen >> 56);
            Transform(instance);

            for (i = 0; i < 4; ++i)
            {
                hash[i] = (byte)(((instance->state[0]) >> (int)(24 - i * 8)) & 0x000000ff);
                hash[i + 4] = (byte)(((instance->state[1]) >> (int)(24 - i * 8)) & 0x000000ff);
                hash[i + 8] = (byte)(((instance->state[2]) >> (int)(24 - i * 8)) & 0x000000ff);
                hash[i + 12] = (byte)((instance->state[3] >> (int)(24 - i * 8)) & 0x000000ff);
                hash[i + 16] = (byte)((instance->state[4] >> (int)(24 - i * 8)) & 0x000000ff);
                hash[i + 20] = (byte)((instance->state[5] >> (int)(24 - i * 8)) & 0x000000ff);
                hash[i + 24] = (byte)((instance->state[6] >> (int)(24 - i * 8)) & 0x000000ff);
                hash[i + 28] = (byte)((instance->state[7] >> (int)(24 - i * 8)) & 0x000000ff);
            }
        }
	}

	unsafe void Start() {
        Stopwatch stopWatch = new Stopwatch();
        stopWatch.Start();

        var file = File.OpenRead(Application.streamingAssetsPath + "/data");

        SHA256 sha256 = new SHA256();
        SHA256.Initialize(&sha256);

        var buffer = new byte[64 * 1024];
        for (;;) {
            var n = file.Read(buffer, 0, buffer.Length);
            if (n == 0) {
                break;
            }

            fixed (byte *p = buffer) {
                SHA256.Update(&sha256, p, n);
            }
        }

        var hash = new NativeArray<byte>(32, Allocator.Temp);
        SHA256.Final(&sha256, hash);

        stopWatch.Stop();

        TimeSpan ts = stopWatch.Elapsed;

        Debug.Log($"{ts.Hours:00}:{ts.Minutes:00}:{ts.Seconds:00}.{ts.Milliseconds / 10:00}");
        Debug.Log($"{hash[0]:X2}{hash[1]:X2}{hash[2]:X2}{hash[3]:X2}{hash[4]:X2}{hash[5]:X2}{hash[6]:X2}{hash[7]:X2}{hash[8]:X2}{hash[9]:X2}{hash[10]:X2}{hash[11]:X2}{hash[12]:X2}{hash[13]:X2}{hash[14]:X2}{hash[15]:X2}{hash[16]:X2}{hash[17]:X2}{hash[18]:X2}{hash[19]:X2}{hash[20]:X2}{hash[21]:X2}{hash[22]:X2}{hash[23]:X2}{hash[24]:X2}{hash[25]:X2}{hash[26]:X2}{hash[27]:X2}{hash[28]:X2}{hash[29]:X2}{hash[30]:X2}{hash[31]:X2}");
	}
}
