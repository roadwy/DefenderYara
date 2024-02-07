
rule PWS_Win32_Lolyda_S{
	meta:
		description = "PWS:Win32/Lolyda.S,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_02_0 = {53 65 72 76 69 63 65 52 6f 75 74 65 45 78 90 09 80 00 90 02 80 48 42 90 02 08 2e 64 6c 6c 90 02 80 53 74 61 72 74 53 65 72 76 69 63 65 45 78 00 53 74 6f 70 53 65 72 76 69 63 65 45 78 90 00 } //01 00 
		$a_00_1 = {61 63 63 6f 75 6e 74 3d 25 73 26 70 61 73 73 77 6f 72 64 } //01 00  account=%s&password
		$a_01_2 = {00 25 73 25 73 25 73 00 } //01 00  ─╳╳s
		$a_01_3 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //01 00  SetWindowsHookExA
		$a_01_4 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //00 00  InternetOpenUrlA
	condition:
		any of ($a_*)
 
}