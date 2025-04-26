
rule Trojan_Win32_LummaC_SXXS_MTB{
	meta:
		description = "Trojan:Win32/LummaC.SXXS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 c1 80 c1 cf 32 0c 02 80 c1 62 88 0c 02 40 83 f8 1a 75 } //1
		$a_01_1 = {0f b6 94 0f d2 9f 07 14 31 ca 89 d6 83 e6 2d 81 f2 ad 00 00 00 8d 14 72 80 c2 f7 88 94 0f d2 9f 07 14 41 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}