
rule Trojan_BAT_Perseus_GNP_MTB{
	meta:
		description = "Trojan:BAT/Perseus.GNP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 1f 0b 28 ?? ?? ?? 06 0b 1f 38 28 ?? ?? ?? 06 0c 02 1c 8d ?? ?? ?? ?? 25 16 72 ?? ?? ?? ?? a2 25 17 06 a2 25 18 72 ?? ?? ?? ?? a2 25 19 07 a2 25 1a 72 ?? ?? ?? ?? a2 25 1b 08 a2 } //10
		$a_80_1 = {50 58 77 59 37 6d 42 44 6d 61 35 68 66 32 4d 6b 46 58 39 35 77 59 79 44 42 63 38 57 42 62 44 66 59 59 35 47 57 67 62 54 67 52 4d 38 48 71 34 59 63 33 } //PXwY7mBDma5hf2MkFX95wYyDBc8WBbDfYY5GWgbTgRM8Hq4Yc3  1
		$a_80_2 = {7a 46 53 33 58 34 38 6e 39 71 33 35 64 5a 61 45 35 35 44 34 79 79 37 5a 37 53 32 33 4e 6b 50 52 62 68 42 35 47 66 68 44 74 } //zFS3X48n9q35dZaE55D4yy7Z7S23NkPRbhB5GfhDt  1
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=12
 
}