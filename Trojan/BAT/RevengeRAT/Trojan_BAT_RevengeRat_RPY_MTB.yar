
rule Trojan_BAT_RevengeRat_RPY_MTB{
	meta:
		description = "Trojan:BAT/RevengeRat.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {46 61 6c 61 73 74 69 6e } //1 Falastin
		$a_03_1 = {a2 0b 05 18 d6 0c 14 0d 09 ?? ?? ?? ?? ?? 13 04 03 4a 04 4a d8 1f 58 d8 08 d6 16 d8 16 d6 13 05 02 } //1
		$a_03_2 = {00 03 8e 69 1f 11 da 17 d6 ?? ?? ?? ?? ?? 13 04 03 1f 10 11 04 16 03 8e 69 1f 10 da } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}