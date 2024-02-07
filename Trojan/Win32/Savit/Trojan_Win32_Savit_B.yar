
rule Trojan_Win32_Savit_B{
	meta:
		description = "Trojan:Win32/Savit.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {8a 54 24 10 8b 4c 24 08 53 8a 1c 08 32 da 88 1c 08 40 3b c6 7c } //01 00 
		$a_01_1 = {f2 ae f7 d1 2b f9 89 75 e0 8b c1 8b f7 8b 7d e0 89 55 ec c1 e9 02 } //01 00 
		$a_01_2 = {57 61 6e 74 20 57 6f 6f 64 20 54 6f 20 45 78 69 74 } //01 00  Want Wood To Exit
		$a_01_3 = {49 50 56 34 2e 62 61 6b } //00 00  IPV4.bak
	condition:
		any of ($a_*)
 
}