
rule Trojan_AndroidOS_ApkLodr_A_MTB{
	meta:
		description = "Trojan:AndroidOS/ApkLodr.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {2e 61 70 6b 00 00 00 00 64 61 6c 76 69 6b 2f 73 79 73 74 65 6d 2f 44 65 78 43 6c 61 73 73 4c 6f 61 64 65 72 } //1
		$a_02_1 = {55 45 73 44 42 42 51 41 43 41 67 49 41 ?? ?? ?? ?? ?? ?? 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 54 41 41 41 41 51 57 35 6b 63 6d 39 70 5a 45 31 68 62 6d 6c 6d 5a 58 4e 30 4c 6e 68 74 62 } //1
		$a_00_2 = {5f 5a 37 6c 6f 61 64 44 65 78 50 37 5f 4a 4e 49 45 6e 76 50 38 5f 6a 6f 62 6a 65 63 74 } //1 _Z7loadDexP7_JNIEnvP8_jobject
		$a_00_3 = {5a 38 65 6d 75 6c 61 74 6f 72 50 37 } //1 Z8emulatorP7
		$a_00_4 = {5a 31 30 64 65 6c 65 74 65 46 69 6c 65 } //1 Z10deleteFile
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}