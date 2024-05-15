
rule Trojan_Win32_Fragtor_NFA_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.NFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {33 ff 3b cf 76 2e 6a e0 58 33 d2 f7 f1 3b 45 90 01 01 1b c0 40 75 1f e8 1c 9e ff ff c7 00 0c 90 00 } //01 00 
		$a_01_1 = {4d 00 4a 00 50 00 47 00 43 00 2e 00 54 00 4d 00 50 00 } //00 00  MJPGC.TMP
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Fragtor_NFA_MTB_2{
	meta:
		description = "Trojan:Win32/Fragtor.NFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {6b 6f 6e 74 61 6b 74 70 6c 75 73 2e 64 65 } //01 00  kontaktplus.de
		$a_01_1 = {68 61 63 6b 65 72 2d 73 70 69 64 65 72 2e 64 65 } //01 00  hacker-spider.de
		$a_01_2 = {73 6d 73 66 61 6b 65 2e 64 65 } //01 00  smsfake.de
		$a_01_3 = {65 72 6f 74 69 6b 73 74 75 64 69 6f 36 39 2e 63 6f 6d } //01 00  erotikstudio69.com
		$a_01_4 = {6b 6f 6e 74 61 6b 74 61 6e 7a 65 69 67 65 6e 64 62 2e 64 65 } //01 00  kontaktanzeigendb.de
		$a_01_5 = {45 53 2a 73 65 6e 64 6d 61 6e } //01 00  ES*sendman
		$a_01_6 = {73 6d 73 2d 63 61 74 2e 64 65 } //00 00  sms-cat.de
	condition:
		any of ($a_*)
 
}