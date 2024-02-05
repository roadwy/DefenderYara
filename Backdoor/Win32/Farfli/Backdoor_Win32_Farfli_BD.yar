
rule Backdoor_Win32_Farfli_BD{
	meta:
		description = "Backdoor:Win32/Farfli.BD,SIGNATURE_TYPE_PEHSTR_EXT,05 00 01 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {b9 79 17 00 00 66 89 08 83 7c 24 } //01 00 
		$a_01_1 = {b9 63 ea 00 00 66 89 08 83 7c 24 } //01 00 
		$a_01_2 = {b9 4c ee 00 00 66 89 08 83 7c 24 } //01 00 
		$a_03_3 = {b4 d8 ff ff 90 09 10 00 e8 90 01 02 00 00 83 c4 0c 3b c3 75 40 81 7c 24 90 00 } //04 00 
		$a_03_4 = {51 8d 54 24 90 01 01 52 bb 90 03 01 01 9e 91 01 00 00 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}