
rule Trojan_Win32_TrickBot_DSY_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.DSY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a 14 01 8b 45 f8 03 45 f4 33 c9 8a 08 33 d1 a1 90 01 04 8b 08 8b 45 18 88 14 08 90 00 } //01 00 
		$a_81_1 = {34 58 56 25 46 4e 7c 6b 4c 38 4c 39 50 54 53 7b 6c 48 24 78 6a 55 31 7e 71 65 45 7e 58 4a 79 78 65 69 64 7a 44 46 4f 53 37 7e 47 6c 41 6e 45 62 68 45 44 6e 4a 59 39 74 54 6c 53 4e 38 68 47 48 78 6d 53 30 3f 35 34 2a 4e 7d 7a 7e 7e 50 49 66 6e 67 78 79 74 71 } //00 00 
	condition:
		any of ($a_*)
 
}