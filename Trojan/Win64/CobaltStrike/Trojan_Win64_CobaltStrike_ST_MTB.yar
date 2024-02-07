
rule Trojan_Win64_CobaltStrike_ST_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.ST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 43 76 6f 4e 75 57 47 62 66 48 52 63 } //01 00  SCvoNuWGbfHRc
		$a_01_1 = {5a 45 78 43 58 4d 61 6d 69 45 53 7a 4b 7a 6b 4e 43 } //01 00  ZExCXMamiESzKzkNC
		$a_01_2 = {65 4c 68 56 50 44 62 59 4c 46 6a 4b 4f 4d } //01 00  eLhVPDbYLFjKOM
		$a_01_3 = {70 4d 48 64 4a 4c 44 6a 4a 6d 56 59 61 71 62 50 43 } //01 00  pMHdJLDjJmVYaqbPC
		$a_01_4 = {75 75 72 57 72 55 42 4e 78 4b 75 4e 56 61 } //01 00  uurWrUBNxKuNVa
		$a_01_5 = {4f 49 64 78 67 49 57 55 45 48 4d } //00 00  OIdxgIWUEHM
	condition:
		any of ($a_*)
 
}