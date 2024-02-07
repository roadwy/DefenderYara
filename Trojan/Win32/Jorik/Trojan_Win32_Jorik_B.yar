
rule Trojan_Win32_Jorik_B{
	meta:
		description = "Trojan:Win32/Jorik.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {8d 04 b6 33 c9 33 d2 89 4c 24 0c 8d 04 80 89 54 24 18 89 4c 24 10 89 4c 24 14 8d 04 80 52 8d 4c 24 28 89 54 24 20 c1 e0 03 } //01 00 
		$a_00_1 = {61 66 21 69 26 64 39 } //01 00  af!i&d9
		$a_00_2 = {4b 69 6c 6c 20 59 6f 75 } //01 00  Kill You
		$a_00_3 = {63 6d 64 2e 65 78 65 20 2f 63 20 22 25 73 22 } //00 00  cmd.exe /c "%s"
	condition:
		any of ($a_*)
 
}