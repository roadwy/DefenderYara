
rule TrojanDropper_AndroidOS_JokerDropper_A{
	meta:
		description = "TrojanDropper:AndroidOS/JokerDropper.A,SIGNATURE_TYPE_DEXHSTR_EXT,28 00 28 00 07 00 00 "
		
	strings :
		$a_00_0 = {78 6e 33 6f 2e 6f 73 73 2d 61 63 63 65 6c 65 72 61 74 65 2e 61 6c 69 79 75 6e 63 73 2e 63 6f 6d } //20 xn3o.oss-accelerate.aliyuncs.com
		$a_01_1 = {6c 6f 61 64 43 6c 61 73 73 } //3 loadClass
		$a_01_2 = {64 61 6c 76 69 6b 2e 73 79 73 74 65 6d 2e 44 65 78 43 6c 61 73 73 4c 6f 61 64 65 72 } //3 dalvik.system.DexClassLoader
		$a_01_3 = {64 61 6c 76 69 6b 2d 63 61 63 68 65 } //3 dalvik-cache
		$a_01_4 = {63 6f 6d 2e 78 6e 33 6f } //5 com.xn3o
		$a_01_5 = {44 65 78 46 69 6c 65 4e 61 6d 65 } //3 DexFileName
		$a_01_6 = {6a 61 76 61 2e 6c 61 6e 67 2e 43 6c 61 73 73 4c 6f 61 64 65 72 } //3 java.lang.ClassLoader
	condition:
		((#a_00_0  & 1)*20+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*5+(#a_01_5  & 1)*3+(#a_01_6  & 1)*3) >=40
 
}