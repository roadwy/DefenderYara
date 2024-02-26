
rule Trojan_Win32_Alien_MA_MTB{
	meta:
		description = "Trojan:Win32/Alien.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {8b 54 24 08 33 c0 85 d2 7e 14 8b 4c 24 04 53 8a 1c 08 80 f3 cc 88 1c 08 40 3b c2 7c f2 5b c3 } //01 00 
		$a_01_1 = {2d 64 65 63 6f 64 65 } //01 00  -decode
		$a_01_2 = {41 6c 6c 20 55 73 65 72 73 5c 4d 73 4d 70 45 6e 67 5c 4d 70 53 76 63 2e 74 78 74 } //00 00  All Users\MsMpEng\MpSvc.txt
	condition:
		any of ($a_*)
 
}