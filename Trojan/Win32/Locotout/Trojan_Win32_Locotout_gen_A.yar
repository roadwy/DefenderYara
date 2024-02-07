
rule Trojan_Win32_Locotout_gen_A{
	meta:
		description = "Trojan:Win32/Locotout.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 06 00 "
		
	strings :
		$a_01_0 = {74 05 50 ff d7 b3 01 56 ff d7 84 db 5f 74 2b e8 } //06 00 
		$a_01_1 = {63 6d 64 20 2f 63 20 6e 65 74 20 73 74 61 72 74 20 25 73 } //01 00  cmd /c net start %s
		$a_01_2 = {6c 69 6e 6b 2e 70 68 70 3f 64 61 74 61 } //01 00  link.php?data
		$a_01_3 = {3f 61 63 74 69 6f 6e 3d 6c 6f 67 6f 75 74 } //01 00  ?action=logout
		$a_01_4 = {3c 64 69 61 70 3e 00 } //01 00 
		$a_01_5 = {64 76 3d 00 76 72 3d 00 6d 65 3d 00 } //01 00  癤=牶=敭=
		$a_01_6 = {61 74 74 25 64 63 6f 6e 74 65 6e 74 } //00 00  att%dcontent
	condition:
		any of ($a_*)
 
}