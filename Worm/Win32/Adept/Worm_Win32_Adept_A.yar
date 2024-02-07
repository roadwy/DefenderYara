
rule Worm_Win32_Adept_A{
	meta:
		description = "Worm:Win32/Adept.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {8a 04 2a 8a 14 31 32 d0 88 14 31 41 3b cf 7c eb } //02 00 
		$a_01_1 = {68 90 00 00 00 52 56 ff 15 } //01 00 
		$a_01_2 = {72 75 2f 66 6f 6c 64 65 72 2e 69 63 6f } //01 00  ru/folder.ico
		$a_01_3 = {3d 73 79 73 74 65 6d 2e 76 62 73 } //01 00  =system.vbs
		$a_01_4 = {53 68 65 6c 6c 42 6f 74 52 } //00 00  ShellBotR
	condition:
		any of ($a_*)
 
}