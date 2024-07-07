
rule Trojan_Win32_LummaC_ASGJ_MTB{
	meta:
		description = "Trojan:Win32/LummaC.ASGJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff 8b 44 24 90 01 01 8d 4c 24 90 01 01 8a 44 04 90 01 01 30 07 e8 90 01 03 00 8b 5c 24 90 01 01 47 8b 54 24 90 01 01 6a 0f 5d 81 ff 90 00 } //2
		$a_03_1 = {0f b6 44 1c 90 01 01 03 c6 33 ed 0f b6 c0 59 89 44 24 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}