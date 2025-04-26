
rule Trojan_BAT_SpySnake_MW_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.MW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_03_0 = {02 07 02 8e 69 5d 02 07 02 8e 69 5d 91 06 07 06 8e 69 5d 91 61 ?? ?? ?? ?? ?? 6e 02 07 17 58 02 8e 69 5d 91 } //10
		$a_01_1 = {67 65 74 53 74 61 6b 65 } //5 getStake
		$a_01_2 = {50 72 6f 6d 6f 43 6f 72 65 2e 50 72 6f 70 65 72 74 69 65 73 } //5 PromoCore.Properties
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5) >=20
 
}
rule Trojan_BAT_SpySnake_MW_MTB_2{
	meta:
		description = "Trojan:BAT/SpySnake.MW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {4e 00 4c 00 58 00 68 00 48 00 57 00 58 00 41 00 53 00 47 00 49 00 51 00 69 00 5a 00 6e 00 2e 00 52 00 59 00 79 00 52 00 71 00 70 00 51 00 63 00 67 00 53 00 56 00 47 00 72 00 6a 00 56 00 } //5 NLXhHWXASGIQiZn.RYyRqpQcgSVGrjV
		$a_01_1 = {68 00 63 00 49 00 4b 00 79 00 6d 00 58 00 56 00 5a 00 41 00 57 00 69 00 6d 00 65 00 4e 00 } //5 hcIKymXVZAWimeN
		$a_03_2 = {13 0e 11 0e 72 d5 04 0c 70 28 ?? ?? ?? 0a 13 0e 11 0e 72 c5 04 0c 70 28 ?? ?? ?? 0a 13 0e 11 0e 72 2d 05 0c 70 28 ?? ?? ?? 0a 13 0e 11 0e 72 dd 04 0c 70 28 ?? ?? ?? 0a 13 0e 11 0e 72 2d 05 0c 70 28 ?? ?? ?? 0a 13 0e 11 0e 72 31 05 0c 70 } //2
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_03_2  & 1)*2) >=12
 
}
rule Trojan_BAT_SpySnake_MW_MTB_3{
	meta:
		description = "Trojan:BAT/SpySnake.MW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 07 28 ?? ?? ?? 0a 03 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0a 7e ?? 00 00 04 06 6f ?? ?? ?? 0a 00 7e ?? 00 00 04 18 6f ?? ?? ?? 0a 00 7e ?? 00 00 04 6f ?? ?? ?? 0a 80 ?? 00 00 04 02 28 ?? ?? ?? 06 0c 08 0d 7e ?? 00 00 04 6f ?? ?? ?? 0a 00 09 13 04 2b 00 11 04 2a } //1
		$a_01_1 = {4d 69 72 61 72 6d 61 72 } //1 Mirarmar
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_3 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_01_4 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_01_5 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_6 = {47 65 74 44 6f 6d 61 69 6e } //1 GetDomain
		$a_01_7 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_8 = {73 65 74 5f 4b 65 79 } //1 set_Key
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}