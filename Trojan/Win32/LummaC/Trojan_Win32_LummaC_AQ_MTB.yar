
rule Trojan_Win32_LummaC_AQ_MTB{
	meta:
		description = "Trojan:Win32/LummaC.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 18 8b 4c 24 1c 8a 44 04 38 30 04 19 85 f6 74 09 6a 01 8b ce e8 } //4
		$a_01_1 = {0f b6 44 2c 38 03 c2 89 74 24 10 0f b6 c0 } //1
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}