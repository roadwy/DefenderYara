
rule Trojan_Win32_LummaC_ASGF_MTB{
	meta:
		description = "Trojan:Win32/LummaC.ASGF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 44 2c 90 01 01 03 c6 0f b6 c0 8a 44 04 90 01 01 30 04 39 8b 4c 24 90 01 01 85 c9 74 90 00 } //4
		$a_01_1 = {64 69 76 75 68 78 49 55 6f } //1 divuhxIUo
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}