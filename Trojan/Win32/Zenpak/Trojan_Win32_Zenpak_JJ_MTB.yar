
rule Trojan_Win32_Zenpak_JJ_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.JJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 07 00 00 01 00 "
		
	strings :
		$a_02_0 = {31 34 24 66 90 02 25 89 0c 10 90 0a 50 00 ff 37 90 00 } //01 00 
		$a_02_1 = {89 0c 10 66 90 0a 50 00 ff 37 90 02 25 31 34 24 90 00 } //01 00 
		$a_02_2 = {31 34 24 81 ff 90 02 25 89 0c 10 90 0a 50 00 ff 37 90 00 } //01 00 
		$a_02_3 = {ff 37 85 ff 90 02 25 31 34 24 90 02 25 89 0c 10 90 00 } //01 00 
		$a_02_4 = {89 0c 10 85 ff 90 0a 50 00 ff 37 90 02 25 31 34 24 90 00 } //01 00 
		$a_02_5 = {31 34 24 85 ff 90 02 25 89 0c 10 90 0a 50 00 ff 37 90 00 } //01 00 
		$a_02_6 = {31 34 24 83 90 02 25 89 0c 10 90 0a 50 00 ff 37 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}