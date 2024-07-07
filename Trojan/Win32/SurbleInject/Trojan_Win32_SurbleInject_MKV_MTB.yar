
rule Trojan_Win32_SurbleInject_MKV_MTB{
	meta:
		description = "Trojan:Win32/SurbleInject.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 ec 44 0f 28 86 90 01 04 0f 11 44 24 90 01 01 0f 28 86 90 01 04 0f 11 44 24 90 01 01 0f 28 86 90 01 04 0f 11 44 24 90 01 01 0f 28 86 90 01 04 0f 11 44 24 90 01 03 24 ff d0 90 00 } //1
		$a_01_1 = {5c 6e 63 6f 62 6a 61 70 69 5c 52 65 6c 65 61 73 65 5c 63 72 79 70 74 73 70 2e 70 64 62 } //1 \ncobjapi\Release\cryptsp.pdb
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}