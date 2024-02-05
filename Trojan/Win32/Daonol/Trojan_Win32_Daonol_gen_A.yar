
rule Trojan_Win32_Daonol_gen_A{
	meta:
		description = "Trojan:Win32/Daonol.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {b9 18 46 00 00 ac 32 c2 80 c2 90 01 01 90 03 03 01 88 46 ff aa e2 90 00 } //01 00 
		$a_03_1 = {bd 19 46 00 00 30 9e 90 01 04 46 90 02 02 ff d7 80 eb 90 01 01 4d 75 90 00 } //01 00 
		$a_03_2 = {bd 19 46 00 00 81 c6 90 01 04 53 46 8a 24 24 30 24 2e 46 90 03 02 04 ff d7 e8 90 01 04 80 eb 90 01 01 4d 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}