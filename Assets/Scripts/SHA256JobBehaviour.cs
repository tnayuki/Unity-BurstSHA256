using UnityEngine;
using Unity.Burst;
using Unity.Collections;
using Unity.Jobs;
using Stopwatch = System.Diagnostics.Stopwatch;
using File = System.IO.File;
using TimeSpan = System.TimeSpan;

public class SHA256JobBehaviour : MonoBehaviour {
	[BurstCompile]
	struct SHA256Job : IJob {
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

            private fixed byte data[64];
            private int datalen;
            private ulong bitlen;

            private fixed uint state[8];

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

            private void Transform()
            {
                uint a, b, c, d, e, f, g, h, i, j, t1, t2;
                var m = stackalloc uint[64];

                for (i = 0, j = 0; i < 16; ++i, j += 4)
                    m[i] = (uint)((data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]));

                for (; i < 64; ++i)
                    m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

                a = state[0];
                b = state[1];
                c = state[2];
                d = state[3];
                e = state[4];
                f = state[5];
                g = state[6];
                h = state[7];

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

                state[0] += a;
                state[1] += b;
                state[2] += c;
                state[3] += d;
                state[4] += e;
                state[5] += f;
                state[6] += g;
                state[7] += h;
            }

            public void Initialize()
            {
                state[0] = 0x6a09e667;
                state[1] = 0xbb67ae85;
                state[2] = 0x3c6ef372;
                state[3] = 0xa54ff53a;
                state[4] = 0x510e527f;
                state[5] = 0x9b05688c;
                state[6] = 0x1f83d9ab;
                state[7] = 0x5be0cd19;
            }

            public void Update(NativeArray<byte> data)
            {
                for (int i = 0; i < data.Length; ++i)
                {
                    this.data[datalen] = data[i];
                    this.datalen++;

                    if (datalen == 64)
                    {
                        Transform();
                        bitlen += 512;
                        datalen = 0;
                    }
                }
            }

            public void Final(NativeArray<byte> hash)
            {
                int i = datalen;

                if (datalen < 56)
                {
                    data[i++] = 0x80;

                    while (i < 56)
                        data[i++] = 0x00;
                }
                else
                {
                    data[i++] = 0x80;

                    while (i < 64)
                        data[i++] = 0x00;

                    Transform();

                    for (i = 0; i < 56;)
                        data[i++] = 0x00;
                }

                bitlen += (ulong)datalen * 8;
                data[63] = (byte)(bitlen);
                data[62] = (byte)(bitlen >> 8);
                data[61] = (byte)(bitlen >> 16);
                data[60] = (byte)(bitlen >> 24);
                data[59] = (byte)(bitlen >> 32);
                data[58] = (byte)(bitlen >> 40);
                data[57] = (byte)(bitlen >> 48);
                data[56] = (byte)(bitlen >> 56);
                Transform();

                for (i = 0; i < 4; ++i)
                {
                    hash[i] = (byte)(((state[0]) >> (int)(24 - i * 8)) & 0x000000ff);
                    hash[i + 4] = (byte)(((state[1]) >> (int)(24 - i * 8)) & 0x000000ff);
                    hash[i + 8] = (byte)(((state[2]) >> (int)(24 - i * 8)) & 0x000000ff);
                    hash[i + 12] = (byte)((state[3] >> (int)(24 - i * 8)) & 0x000000ff);
                    hash[i + 16] = (byte)((state[4] >> (int)(24 - i * 8)) & 0x000000ff);
                    hash[i + 20] = (byte)((state[5] >> (int)(24 - i * 8)) & 0x000000ff);
                    hash[i + 24] = (byte)((state[6] >> (int)(24 - i * 8)) & 0x000000ff);
                    hash[i + 28] = (byte)((state[7] >> (int)(24 - i * 8)) & 0x000000ff);
                }
            }
        }

        [ReadOnly]
		public NativeArray<byte> data;
		[WriteOnly]
		public NativeArray<byte> hash;

		public void Execute() {
			var sha256 = new SHA256();
            sha256.Initialize();

            sha256.Update(data);
            sha256.Final(hash);
		}
	}

	private JobHandle jobHandle;
	private bool completed;

	private NativeArray<byte> data;
	private NativeArray<byte> hash;

    private Stopwatch stopWatch = new Stopwatch();

	void Start() {
        stopWatch.Start();

        var mmf = new NativeMemoryMappedFile<byte>(Application.streamingAssetsPath + "/data");
        data = mmf.AsArray();

        hash = new NativeArray<byte>(32, Allocator.Persistent);

		var job = new SHA256Job() {
			data = data,
            hash = hash
		};

		jobHandle = job.Schedule();
	}

	void Update() {
		if  (!completed && jobHandle.IsCompleted) {
			completed = true;

			jobHandle.Complete();

            stopWatch.Stop();

            TimeSpan ts = stopWatch.Elapsed;

            Debug.Log($"{ts.Hours:00}:{ts.Minutes:00}:{ts.Seconds:00}.{ts.Milliseconds / 10:00}");
		    Debug.Log($"{hash[0]:X2}{hash[1]:X2}{hash[2]:X2}{hash[3]:X2}{hash[4]:X2}{hash[5]:X2}{hash[6]:X2}{hash[7]:X2}{hash[8]:X2}{hash[9]:X2}{hash[10]:X2}{hash[11]:X2}{hash[12]:X2}{hash[13]:X2}{hash[14]:X2}{hash[15]:X2}{hash[16]:X2}{hash[17]:X2}{hash[18]:X2}{hash[19]:X2}{hash[20]:X2}{hash[21]:X2}{hash[22]:X2}{hash[23]:X2}{hash[24]:X2}{hash[25]:X2}{hash[26]:X2}{hash[27]:X2}{hash[28]:X2}{hash[29]:X2}{hash[30]:X2}{hash[31]:X2}");

			hash.Dispose();
		}
	}
}
