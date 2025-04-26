
rule Trojan_BAT_Heracles_AH_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 03 11 00 11 02 11 00 8e 69 5d 91 7e ?? ?? ?? 04 11 02 91 61 d2 6f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Heracles_AH_MTB_2{
	meta:
		description = "Trojan:BAT/Heracles.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 06 18 5b 08 06 18 6f 15 00 00 0a 1f 10 28 16 00 00 0a 9c 06 18 58 0a 06 09 32 e3 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_BAT_Heracles_AH_MTB_3{
	meta:
		description = "Trojan:BAT/Heracles.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 1a fe 01 2c 08 72 bf 11 00 70 0a 1b 0c 00 08 1c fe 01 2c 06 07 17 d6 0b 1d 0c 00 08 1b fe 01 2c 07 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Heracles_AH_MTB_4{
	meta:
		description = "Trojan:BAT/Heracles.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 8e 2d 0a 12 01 fe 15 02 00 00 1b 07 2a 7e ?? ?? ?? 0a 0a 02 7b ?? ?? ?? 04 0a 03 16 06 03 8e 69 28 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Heracles_AH_MTB_5{
	meta:
		description = "Trojan:BAT/Heracles.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {18 5b 0b 16 0d 2b 27 72 01 00 00 70 02 09 18 5a 18 6f 09 00 00 0a 28 0a 00 00 0a 1f 10 28 0b 00 00 0a 13 04 06 09 11 04 d2 9c 09 17 58 0d 09 07 32 d5 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Heracles_AH_MTB_6{
	meta:
		description = "Trojan:BAT/Heracles.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0c 16 13 0d 2b 14 08 11 0d 8f ?? ?? ?? 01 25 47 1e 61 d2 52 11 0d 17 58 13 0d 11 0d 08 8e 69 32 e5 } //2
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}