
rule Trojan_Win32_Viewsure_E_dha{
	meta:
		description = "Trojan:Win32/Viewsure.E!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {31 00 30 00 33 00 2e 00 31 00 30 00 33 00 2e 00 31 00 32 00 38 00 2e 00 34 00 32 00 } //02 00  103.103.128.42
		$a_01_1 = {73 00 63 00 20 00 71 00 75 00 65 00 72 00 79 00 20 00 73 00 74 00 61 00 74 00 65 00 3d 00 20 00 61 00 6c 00 6c 00 } //01 00  sc query state= all
		$a_01_2 = {64 00 69 00 72 00 20 00 63 00 3a 00 5c 00 75 00 73 00 65 00 72 00 73 00 5c 00 25 00 77 00 73 00 5c 00 64 00 65 00 73 00 6b 00 74 00 6f 00 70 00 } //01 00  dir c:\users\%ws\desktop
		$a_01_3 = {41 00 63 00 63 00 65 00 70 00 74 00 3a 00 20 00 74 00 65 00 78 00 74 00 2f 00 68 00 74 00 6d 00 6c 00 2c 00 20 00 61 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 2f 00 78 00 68 00 74 00 6d 00 6c 00 2b 00 78 00 6d 00 6c 00 2c 00 20 00 69 00 6d 00 61 00 67 00 65 00 2f 00 6a 00 78 00 72 00 2c 00 } //01 00  Accept: text/html, application/xhtml+xml, image/jxr,
		$a_01_4 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 25 00 77 00 73 00 } //00 00  cmd.exe /c %ws
	condition:
		any of ($a_*)
 
}