
rule Backdoor_Win32_ShadowHammer_A_dha{
	meta:
		description = "Backdoor:Win32/ShadowHammer.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {6a 40 68 00 10 00 00 68 00 90 01 02 00 6a 00 ff 15 90 00 } //0a 00 
		$a_03_1 = {ad ab e2 fc 58 05 90 01 02 00 00 ff d0 90 00 } //0a 00 
		$a_00_2 = {41 53 55 53 54 65 4b 20 43 6f 6d 70 75 74 65 72 20 49 6e 63 2e 31 } //00 00  ASUSTeK Computer Inc.1
		$a_00_3 = {5d 04 00 00 90 d3 03 80 5c 26 00 00 91 d3 03 80 00 00 01 00 08 00 10 00 af 01 41 67 65 6e } //74 54 
	condition:
		any of ($a_*)
 
}