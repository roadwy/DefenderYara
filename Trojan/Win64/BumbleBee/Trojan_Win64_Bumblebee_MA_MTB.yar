
rule Trojan_Win64_Bumblebee_MA_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 5a 74 6d 65 49 30 33 } //01 00 
		$a_01_1 = {5a 6d 77 51 68 65 30 65 66 } //01 00 
		$a_01_2 = {4e 45 73 4d 46 } //01 00 
		$a_01_3 = {76 63 73 66 69 6c 65 } //01 00 
		$a_01_4 = {51 58 5a 36 48 } //00 00 
	condition:
		any of ($a_*)
 
}