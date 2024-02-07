
rule Trojan_Win32_Cuffahlt_B{
	meta:
		description = "Trojan:Win32/Cuffahlt.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {2d 2d 2d 2d 2d 42 45 47 49 4e 20 52 53 41 20 50 52 49 56 41 54 45 20 4b 45 59 2d 2d 2d 2d 2d 90 02 10 00 4d 49 49 45 70 51 49 42 41 41 4b 43 41 51 45 41 79 6b 73 49 62 2b 79 4c 59 48 66 72 67 44 51 75 90 00 } //01 00 
		$a_01_1 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 57 69 6e 33 32 5f 42 61 73 65 42 6f 61 72 64 } //01 00  SELECT * FROM Win32_BaseBoard
		$a_01_2 = {63 6d 64 2e 65 78 65 20 2f 43 20 69 70 63 6f 6e 61 65 69 } //01 00  cmd.exe /C ipconaei
		$a_01_3 = {43 65 72 74 73 46 46 2e 64 61 74 00 43 65 72 74 73 4f 50 2e 64 61 74 } //00 00 
		$a_00_4 = {5d 04 00 } //00 12 
	condition:
		any of ($a_*)
 
}