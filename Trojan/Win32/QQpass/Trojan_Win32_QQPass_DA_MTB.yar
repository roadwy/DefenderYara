
rule Trojan_Win32_QQPass_DA_MTB{
	meta:
		description = "Trojan:Win32/QQPass.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 55 e2 8b 45 c8 80 ea 03 32 55 e3 88 14 30 3b 5e f8 0f 8f } //01 00 
		$a_81_1 = {4b 4c 4a 45 57 45 52 48 73 64 77 71 65 68 32 33 32 31 31 21 40 61 73 64 71 53 41 44 77 65 } //01 00  KLJEWERHsdwqeh23211!@asdqSADwe
		$a_81_2 = {42 52 45 53 55 5a 43 44 59 2e 6a 70 67 } //01 00  BRESUZCDY.jpg
		$a_81_3 = {77 61 68 61 68 61 } //00 00  wahaha
	condition:
		any of ($a_*)
 
}