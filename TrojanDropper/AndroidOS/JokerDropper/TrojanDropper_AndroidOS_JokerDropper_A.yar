
rule TrojanDropper_AndroidOS_JokerDropper_A{
	meta:
		description = "TrojanDropper:AndroidOS/JokerDropper.A,SIGNATURE_TYPE_DEXHSTR_EXT,28 00 28 00 07 00 00 14 00 "
		
	strings :
		$a_00_0 = {78 6e 33 6f 2e 6f 73 73 2d 61 63 63 65 6c 65 72 61 74 65 2e 61 6c 69 79 75 6e 63 73 2e 63 6f 6d } //03 00  xn3o.oss-accelerate.aliyuncs.com
		$a_01_1 = {6c 6f 61 64 43 6c 61 73 73 } //03 00  loadClass
		$a_01_2 = {64 61 6c 76 69 6b 2e 73 79 73 74 65 6d 2e 44 65 78 43 6c 61 73 73 4c 6f 61 64 65 72 } //03 00  dalvik.system.DexClassLoader
		$a_01_3 = {64 61 6c 76 69 6b 2d 63 61 63 68 65 } //05 00  dalvik-cache
		$a_01_4 = {63 6f 6d 2e 78 6e 33 6f } //03 00  com.xn3o
		$a_01_5 = {44 65 78 46 69 6c 65 4e 61 6d 65 } //03 00  DexFileName
		$a_01_6 = {6a 61 76 61 2e 6c 61 6e 67 2e 43 6c 61 73 73 4c 6f 61 64 65 72 } //00 00  java.lang.ClassLoader
		$a_00_7 = {5d 04 00 00 24 0e 05 80 5c 31 00 00 25 0e 05 80 00 00 01 00 } //08 00 
	condition:
		any of ($a_*)
 
}