
rule Trojan_BAT_Donut_NEAA_MTB{
	meta:
		description = "Trojan:BAT/Donut.NEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {08 03 2d 18 07 06 28 1d 00 00 0a 72 90 01 01 09 00 70 6f 1e 00 00 0a 6f 23 00 00 0a 2b 16 07 06 28 1d 00 00 0a 72 90 01 01 09 00 70 6f 1e 00 00 0a 6f 24 00 00 0a 17 73 25 00 00 0a 0d 09 02 16 02 8e 69 90 00 } //02 00 
		$a_01_1 = {73 65 74 5f 57 69 6e 64 6f 77 53 74 79 6c 65 } //02 00  set_WindowStyle
		$a_01_2 = {53 00 65 00 6c 00 65 00 63 00 74 00 20 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 4c 00 69 00 6e 00 65 00 2c 00 20 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 49 00 44 00 20 00 66 00 72 00 6f 00 6d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 } //02 00  Select CommandLine, ProcessID from Win32_Process
		$a_01_3 = {5a 57 4d 32 4d 7a 4a 6d 5a 44 6b 74 4d 54 59 35 4e 43 30 30 5a 6a 52 68 4c 54 6c 69 5a 6d 59 74 5a 6a 49 77 4e 6a 41 77 5a 54 4d 33 4f 54 67 78 } //00 00  ZWM2MzJmZDktMTY5NC00ZjRhLTliZmYtZjIwNjAwZTM3OTgx
	condition:
		any of ($a_*)
 
}