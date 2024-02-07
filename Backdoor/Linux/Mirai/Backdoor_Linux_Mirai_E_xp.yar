
rule Backdoor_Linux_Mirai_E_xp{
	meta:
		description = "Backdoor:Linux/Mirai.E!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 06 00 00 02 00 "
		
	strings :
		$a_00_0 = {53 65 6c 66 20 52 65 70 20 46 75 63 6b 69 6e 67 20 4e 65 54 69 53 20 61 6e 64 20 54 68 69 73 69 74 79 20 30 6e 20 55 72 20 46 75 43 6b 49 6e 47 20 46 6f 52 65 48 65 41 64 20 57 65 20 42 69 47 20 4c 33 33 54 20 48 61 78 45 72 53 } //01 00  Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We BiG L33T HaxErS
		$a_00_1 = {42 41 4e 4b 54 59 20 44 44 4f 53 20 46 4f 52 20 39 31 } //01 00  BANKTY DDOS FOR 91
		$a_00_2 = {2f 78 33 38 2f 78 46 4a 2f 78 39 33 2f 78 49 44 2f 78 39 41 2f 78 33 38 2f 78 46 4a 2f 78 39 33 2f 78 49 44 2f 78 39 41 2f } //01 00  /x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/
		$a_00_3 = {73 75 63 6b 6d 61 64 69 63 6b } //01 00  suckmadick
		$a_00_4 = {63 6f 6e 73 69 64 65 72 74 6f 67 6f 6f 66 66 6c 69 6e 65 74 79 76 6d } //01 00  considertogoofflinetyvm
		$a_00_5 = {6e 70 78 58 6f 75 64 69 66 46 65 45 67 47 61 41 43 53 63 73 } //00 00  npxXoudifFeEgGaACScs
		$a_00_6 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}