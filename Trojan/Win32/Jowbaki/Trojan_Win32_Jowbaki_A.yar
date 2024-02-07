
rule Trojan_Win32_Jowbaki_A{
	meta:
		description = "Trojan:Win32/Jowbaki.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 04 00 "
		
	strings :
		$a_01_0 = {6c 00 6d 00 73 00 5f 00 6a 00 6f 00 77 00 62 00 61 00 6b 00 } //02 00  lms_jowbak
		$a_03_1 = {68 00 08 00 00 e8 90 01 02 00 00 59 8b d8 68 d0 07 00 00 ff 15 90 00 } //02 00 
		$a_01_2 = {75 12 8b 71 14 c1 e6 1d c1 fe 1f eb 07 33 f6 46 eb 02 33 f6 8b 41 14 c1 e0 1e c1 f8 1f 3b c6 } //01 00 
		$a_01_3 = {2f 00 75 00 74 00 69 00 6c 00 73 00 2f 00 69 00 6e 00 65 00 74 00 5f 00 69 00 64 00 5f 00 6e 00 6f 00 74 00 69 00 66 00 79 00 2e 00 70 00 68 00 70 00 } //01 00  /utils/inet_id_notify.php
		$a_01_4 = {72 00 6d 00 61 00 6e 00 73 00 79 00 73 00 2e 00 72 00 75 00 } //00 00  rmansys.ru
		$a_00_5 = {5d 04 00 00 41 } //7c 03 
	condition:
		any of ($a_*)
 
}