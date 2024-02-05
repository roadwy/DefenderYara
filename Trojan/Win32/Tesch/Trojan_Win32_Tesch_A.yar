
rule Trojan_Win32_Tesch_A{
	meta:
		description = "Trojan:Win32/Tesch.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {6a 01 8d 46 14 50 8b 46 20 ff 70 14 ff 15 90 01 04 83 f8 ff 75 90 01 01 ff 76 20 56 90 00 } //01 00 
		$a_03_1 = {6a 23 8d 47 04 68 90 01 04 50 c7 07 32 33 0d 0a e8 90 01 04 6a 29 66 c7 47 27 0d 0a 90 00 } //01 00 
		$a_03_2 = {50 c7 06 32 33 0d 0a e8 90 01 04 83 c4 1c 66 c7 46 27 0d 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}