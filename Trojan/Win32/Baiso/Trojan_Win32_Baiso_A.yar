
rule Trojan_Win32_Baiso_A{
	meta:
		description = "Trojan:Win32/Baiso.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {26 41 67 65 6e 74 3d 25 73 26 76 65 72 73 69 6f 6e 3d 25 73 26 69 6e 66 6f 76 65 72 73 69 6f 6e 3d 25 73 } //01 00  &Agent=%s&version=%s&infoversion=%s
		$a_00_1 = {75 70 64 61 74 65 5c 75 70 64 61 74 65 66 69 6c 65 2e 6c 73 74 } //01 00  update\updatefile.lst
		$a_00_2 = {5c 73 79 73 75 70 64 61 74 65 2e 69 6e 69 00 00 5c 73 79 73 6f 70 74 69 6f 6e 2e 69 6e 69 } //01 00 
		$a_01_3 = {73 65 6c 66 55 70 64 61 74 65 00 00 72 74 00 00 75 70 2e 64 61 74 } //01 00 
		$a_00_4 = {77 61 69 74 64 6f 77 6e 2e 6c 73 74 } //01 00  waitdown.lst
		$a_00_5 = {49 6e 74 65 72 6e 65 74 43 6f 6e 6e 65 63 74 } //01 00  InternetConnect
		$a_00_6 = {53 65 72 76 69 63 65 20 52 75 6e 6e 65 64 20 4e 6f 77 21 } //01 00  Service Runned Now!
		$a_00_7 = {6e 6f 74 20 66 6f 75 6e 64 20 73 79 73 74 65 6d 20 64 69 72 65 63 74 6f 72 79 21 } //00 00  not found system directory!
	condition:
		any of ($a_*)
 
}