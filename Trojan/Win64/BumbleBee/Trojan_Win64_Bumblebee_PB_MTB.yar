
rule Trojan_Win64_Bumblebee_PB_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 04 00 "
		
	strings :
		$a_03_0 = {41 8b 0c 80 41 31 0c 90 90 41 8b 90 02 04 00 00 23 90 01 01 7d 90 00 } //04 00 
		$a_03_1 = {41 8b 0c 80 41 31 0c 90 90 41 8b 8e 90 02 04 00 00 41 23 ce 7d 90 00 } //01 00 
		$a_01_2 = {4f 62 6f 58 62 51 58 4d 50 42 } //01 00  OboXbQXMPB
		$a_01_3 = {4c 4f 47 31 37 66 76 } //00 00  LOG17fv
	condition:
		any of ($a_*)
 
}