
rule Trojan_Win32_TrickBot_DA_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a d0 0a 44 24 90 01 01 f6 d2 f6 d1 0a d1 22 d0 8b 44 24 90 01 01 88 10 90 02 04 83 6c 24 90 01 01 01 89 44 24 90 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_TrickBot_DA_MTB_2{
	meta:
		description = "Trojan:Win32/TrickBot.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c1 51 b9 90 01 01 00 00 00 33 d2 f7 f1 59 8a 04 13 30 04 0e 41 3b f9 75 90 00 } //01 00 
		$a_03_1 = {8b 44 24 04 a8 03 75 90 01 01 8b 10 83 c0 04 8b ca 81 ea 01 01 01 01 81 e2 80 80 80 80 74 eb f7 d1 23 d1 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}