
rule Trojan_Win32_LummaC_ASGH_MTB{
	meta:
		description = "Trojan:Win32/LummaC.ASGH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 44 3c 90 01 01 03 c6 59 59 8b 4c 24 90 01 01 0f b6 c0 8a 44 04 90 01 01 30 04 29 45 3b ac 24 90 00 } //4
		$a_01_1 = {64 61 69 78 69 41 69 73 } //1 daixiAis
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}