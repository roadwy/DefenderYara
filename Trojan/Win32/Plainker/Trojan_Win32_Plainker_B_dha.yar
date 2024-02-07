
rule Trojan_Win32_Plainker_B_dha{
	meta:
		description = "Trojan:Win32/Plainker.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 08 00 00 02 00 "
		
	strings :
		$a_01_0 = {73 79 73 61 64 6d 69 6e 6e 65 77 73 2e 69 6e 66 6f } //02 00  sysadminnews.info
		$a_01_1 = {77 69 6e 64 6f 77 73 75 70 64 61 74 65 63 64 6e 2e 63 6f 6d } //02 00  windowsupdatecdn.com
		$a_01_2 = {5c 42 61 63 6b 44 6f 72 4c 61 73 74 5c } //02 00  \BackDorLast\
		$a_01_3 = {63 6d 64 2e 65 78 65 20 2f 43 20 70 69 6e 67 20 31 2e 31 2e 31 2e 31 20 2d 6e 20 31 20 2d 77 20 33 30 30 30 20 3e 20 4e 75 6c 20 26 20 64 65 6c 20 2f 66 20 2f 71 } //02 00  cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & del /f /q
		$a_01_4 = {7b 25 30 38 78 2d 25 30 34 68 78 2d 25 30 34 68 78 2d 25 30 32 68 68 78 25 30 32 68 68 78 2d 25 30 32 68 68 78 25 30 32 68 68 78 25 30 32 68 68 78 25 30 32 68 68 78 25 30 32 68 68 78 25 30 32 68 68 78 7d } //01 00  {%08x-%04hx-%04hx-%02hhx%02hhx-%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx}
		$a_01_5 = {70 72 78 61 64 72 3d } //01 00  prxadr=
		$a_01_6 = {2d 6d 79 66 69 6c 65 2d 2d } //01 00  -myfile--
		$a_01_7 = {44 65 66 61 75 6c 74 2e 61 73 70 78 } //00 00  Default.aspx
	condition:
		any of ($a_*)
 
}