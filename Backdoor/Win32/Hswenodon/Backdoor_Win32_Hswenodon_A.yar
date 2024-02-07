
rule Backdoor_Win32_Hswenodon_A{
	meta:
		description = "Backdoor:Win32/Hswenodon.A,SIGNATURE_TYPE_PEHSTR,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 75 70 65 72 6e 6f 64 65 5f 63 6f 6e 2e 64 6c 6c } //01 00  supernode_con.dll
		$a_01_1 = {25 73 5c 72 72 2e 62 61 74 } //01 00  %s\rr.bat
		$a_01_2 = {70 69 6e 67 20 2d 6e 20 35 20 31 32 37 2e 30 2e 30 2e 31 } //02 00  ping -n 5 127.0.0.1
		$a_01_3 = {25 73 5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 22 25 73 22 2c 48 77 6d 6f 6e 53 65 72 76 65 72 4d 61 69 6e } //01 00  %s\rundll32.exe "%s",HwmonServerMain
		$a_01_4 = {6e 65 74 20 73 74 61 72 74 20 25 73 } //01 00  net start %s
		$a_01_5 = {53 65 72 76 65 72 3a 20 6e 67 69 6e 78 2f 31 2e 39 2e 31 32 } //01 00  Server: nginx/1.9.12
		$a_01_6 = {48 77 6d 6f 6e 57 69 6e 64 6f 77 } //00 00  HwmonWindow
		$a_01_7 = {00 5d 04 00 } //00 80 
	condition:
		any of ($a_*)
 
}