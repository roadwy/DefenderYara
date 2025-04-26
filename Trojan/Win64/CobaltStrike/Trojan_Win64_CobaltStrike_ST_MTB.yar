
rule Trojan_Win64_CobaltStrike_ST_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.ST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 45 b8 48 8b 55 e0 4c 8b 45 b0 8a 4d af 42 32 0c 02 88 08 48 8b 45 08 48 83 c0 01 48 89 45 a0 0f 92 c0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_CobaltStrike_ST_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.ST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 43 76 6f 4e 75 57 47 62 66 48 52 63 } //1 SCvoNuWGbfHRc
		$a_01_1 = {5a 45 78 43 58 4d 61 6d 69 45 53 7a 4b 7a 6b 4e 43 } //1 ZExCXMamiESzKzkNC
		$a_01_2 = {65 4c 68 56 50 44 62 59 4c 46 6a 4b 4f 4d } //1 eLhVPDbYLFjKOM
		$a_01_3 = {70 4d 48 64 4a 4c 44 6a 4a 6d 56 59 61 71 62 50 43 } //1 pMHdJLDjJmVYaqbPC
		$a_01_4 = {75 75 72 57 72 55 42 4e 78 4b 75 4e 56 61 } //1 uurWrUBNxKuNVa
		$a_01_5 = {4f 49 64 78 67 49 57 55 45 48 4d } //1 OIdxgIWUEHM
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}