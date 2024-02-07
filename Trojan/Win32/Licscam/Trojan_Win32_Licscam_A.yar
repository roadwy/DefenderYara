
rule Trojan_Win32_Licscam_A{
	meta:
		description = "Trojan:Win32/Licscam.A,SIGNATURE_TYPE_PEHSTR,1f 00 1f 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {26 63 76 76 3d 00 26 65 6d 3d 00 26 65 79 3d 00 } //0a 00  挦癶=攦㵭☀祥=
		$a_01_1 = {68 74 74 70 3a 2f 2f 62 65 61 75 74 79 62 72 69 65 66 2e 63 6f 6d 2f 63 2f 67 61 74 65 2e 70 68 70 } //0a 00  http://beautybrief.com/c/gate.php
		$a_01_2 = {4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 36 2e 30 3b 20 57 69 6e 33 32 29 00 50 4f 53 54 00 } //01 00 
		$a_01_3 = {41 63 74 69 76 61 74 69 6f 6e 20 6f 66 20 57 69 6e 64 6f 77 73 } //01 00  Activation of Windows
		$a_01_4 = {4d 69 63 72 6f 73 6f 66 74 20 70 69 72 61 63 79 20 63 6f 6e 74 72 6f 6c } //00 00  Microsoft piracy control
	condition:
		any of ($a_*)
 
}