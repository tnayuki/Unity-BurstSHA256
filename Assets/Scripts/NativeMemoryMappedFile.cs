using Unity.Collections;
using Unity.Collections.LowLevel.Unsafe;
using System.IO.MemoryMappedFiles;

[NativeContainer]
public unsafe struct NativeMemoryMappedFile<T> : System.IDisposable where T: struct {
	private MemoryMappedFile memoryMappedFile;
	private MemoryMappedViewAccessor memoryMappedViewAccessor;

	unsafe byte *ptr;

	public NativeMemoryMappedFile(string path) {
		memoryMappedFile = MemoryMappedFile.CreateFromFile(path, System.IO.FileMode.Open, null, 0, MemoryMappedFileAccess.Read);
		memoryMappedViewAccessor = memoryMappedFile.CreateViewAccessor(0, 0, MemoryMappedFileAccess.Read);

		unsafe {
			ptr = null;
			memoryMappedViewAccessor.SafeMemoryMappedViewHandle.AcquirePointer(ref ptr);
		}
	}

	public void Dispose() {
		memoryMappedViewAccessor.Dispose();
		memoryMappedFile.Dispose();
	}

	public NativeArray<T> AsArray() {
		var array = NativeArrayUnsafeUtility.ConvertExistingDataToNativeArray<T>(ptr, (int)(memoryMappedViewAccessor.Capacity / UnsafeUtility.SizeOf<T>()), Allocator.Invalid);

#if ENABLE_UNITY_COLLECTIONS_CHECKS
		NativeArrayUnsafeUtility.SetAtomicSafetyHandle(ref array, AtomicSafetyHandle.Create());
#endif
		return array;
	}
}
