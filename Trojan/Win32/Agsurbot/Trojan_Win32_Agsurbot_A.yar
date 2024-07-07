
rule Trojan_Win32_Agsurbot_A{
	meta:
		description = "Trojan:Win32/Agsurbot.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 52 47 55 53 5f 4e 4f } //1 ARGUS_NO
		$a_01_1 = {62 6f 74 2f 61 64 77 6f 72 73 2e 70 68 70 } //1 bot/adwors.php
		$a_01_2 = {62 6f 74 2f 67 6f 6f 67 6c 65 2e 70 68 70 } //1 bot/google.php
		$a_01_3 = {41 64 77 6f 72 73 53 65 61 72 63 68 54 69 6d 65 72 54 69 6d 65 72 } //1 AdworsSearchTimerTimer
		$a_03_4 = {3c 41 20 69 64 3d 22 70 61 90 02 03 22 20 68 72 65 66 3d 22 00 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=4
 
}