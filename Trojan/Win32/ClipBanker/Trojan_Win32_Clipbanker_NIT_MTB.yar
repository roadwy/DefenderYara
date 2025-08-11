
rule Trojan_Win32_ClipBanker_NIT_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 68 65 63 76 62 7a } //2 shecvbz
		$a_01_1 = {6f 77 6e 65 72 20 64 65 61 64 } //2 owner dead
		$a_01_2 = {46 6c 75 73 68 50 72 6f 63 65 73 73 57 72 69 74 65 42 75 66 66 65 72 73 } //1 FlushProcessWriteBuffers
		$a_01_3 = {70 70 56 69 72 74 75 61 6c 50 72 6f 63 65 73 73 6f 72 52 6f 6f 74 73 } //1 ppVirtualProcessorRoots
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}