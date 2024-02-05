
rule Trojan_Win32_Sefnit_A{
	meta:
		description = "Trojan:Win32/Sefnit.A,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {2e 64 6c 6c 00 44 6c 6c 49 6e 69 74 00 44 6c 6c 49 6e 73 74 61 6c 6c 00 00 } //01 00 
		$a_03_1 = {b8 b7 00 00 00 90 03 01 01 eb e9 90 00 } //01 00 
		$a_03_2 = {81 ec bc 06 00 00 90 17 03 01 01 05 eb e9 68 04 01 00 00 90 00 } //01 00 
		$a_03_3 = {ff d2 85 c0 90 02 06 c7 45 f8 00 00 00 00 e9 90 00 } //01 00 
		$a_01_4 = {8f 45 f4 81 75 f4 } //01 00 
		$a_03_5 = {01 40 00 80 90 09 03 00 c7 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}