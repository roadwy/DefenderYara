
rule Trojan_Win32_Oficla_T{
	meta:
		description = "Trojan:Win32/Oficla.T,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 05 00 00 14 00 "
		
	strings :
		$a_03_0 = {8d 55 ec b8 53 00 00 00 e8 90 01 04 ff 75 ec 8d 55 90 01 01 b8 90 03 01 01 59 6f 00 00 00 90 00 } //0a 00 
		$a_03_1 = {8a 0c 03 80 f1 90 01 01 88 0c 03 40 4a 75 f3 90 00 } //0a 00 
		$a_01_2 = {8a 14 03 80 f2 0d 88 14 03 40 4e 75 f3 } //0a 00 
		$a_01_3 = {8a 0c 13 80 f1 0d 88 0c 13 42 48 75 f3 } //01 00 
		$a_01_4 = {75 73 65 72 69 6e 69 74 78 78 2e 65 78 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}