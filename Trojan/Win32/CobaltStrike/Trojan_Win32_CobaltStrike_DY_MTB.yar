
rule Trojan_Win32_CobaltStrike_DY_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.DY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {80 f4 01 f6 d4 51 81 c1 f1 00 00 00 51 59 b9 c5 00 00 00 41 81 c1 0e 01 00 00 49 b9 7e 00 00 00 87 c9 41 41 87 c9 59 d0 cc 8a 04 33 32 c4 32 07 88 07 47 4b 79 02 89 d3 51 56 53 57 52 87 d6 83 ce 51 4f 81 f2 9b 00 00 00 81 c1 07 01 00 00 81 f3 5e 01 00 00 87 f6 83 f7 23 5a 5f 5b 5e 59 49 75 } //01 00 
		$a_01_1 = {48 55 42 20 44 4f 47 53 20 59 4f 55 52 53 45 4c 46 20 48 4f 4c 4c 4f 57 20 52 45 50 52 45 53 45 4e 54 20 4c 41 4e 44 53 20 4b 4e 4f 43 4b } //00 00 
	condition:
		any of ($a_*)
 
}