
rule Trojan_BAT_Razy_NL_MTB{
	meta:
		description = "Trojan:BAT/Razy.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_80_0 = {73 6f 66 74 2e 66 69 6c 65 73 68 69 70 6f 6f 2e 63 6f 6d 2f 66 6f 72 64 2f 63 61 63 68 65 5f 75 70 64 61 74 65 2e 70 68 70 } //soft.fileshipoo.com/ford/cache_update.php  5
		$a_80_1 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 41 6e 74 69 76 69 72 75 73 50 72 6f 64 75 63 74 } //SELECT * FROM AntivirusProduct  1
		$a_80_2 = {5c 72 6f 6f 74 5c 53 65 63 75 72 69 74 79 43 65 6e 74 65 72 } //\root\SecurityCenter  1
		$a_80_3 = {2f 43 20 73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 52 55 20 53 59 53 54 45 4d 20 2f 73 63 20 6d 69 6e 75 74 65 20 2f 6d 6f } ///C schtasks /create /RU SYSTEM /sc minute /mo  1
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=8
 
}