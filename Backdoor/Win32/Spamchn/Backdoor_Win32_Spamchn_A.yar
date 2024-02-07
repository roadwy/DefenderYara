
rule Backdoor_Win32_Spamchn_A{
	meta:
		description = "Backdoor:Win32/Spamchn.A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 07 00 05 00 00 03 00 "
		
	strings :
		$a_01_0 = {2c 53 75 62 48 6f 73 74 3a } //03 00  ,SubHost:
		$a_01_1 = {23 31 3c 3c 3c 3c 3c 49 44 43 3c 3c 3c 3c 3c 3c 3c 3c 3d 43 51 5d 54 53 5c 3c 3c 3c 3c 3c 3c 3c 3c 43 48 73 49 76 55 72 69 5d 49 } //02 00  #1<<<<<IDC<<<<<<<<=CQ]TS\<<<<<<<<CHsIvUri]I
		$a_01_2 = {41 63 63 65 70 74 2d 4c 61 6e 67 75 61 67 65 3a 20 7a 68 2d 63 6e } //01 00  Accept-Language: zh-cn
		$a_01_3 = {77 69 6e 64 6f 77 2e 6c 6f 63 61 74 69 6f 6e } //01 00  window.location
		$a_01_4 = {73 76 63 68 6f 73 74 } //00 00  svchost
	condition:
		any of ($a_*)
 
}