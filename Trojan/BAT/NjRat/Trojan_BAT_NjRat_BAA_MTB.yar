
rule Trojan_BAT_NjRat_BAA_MTB{
	meta:
		description = "Trojan:BAT/NjRat.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 11 09 11 0d 11 0e 11 0c 11 0e 59 ?? ?? ?? ?? ?? 13 0f 11 0f 16 fe 01 16 fe 01 13 13 11 13 2d 02 2b 14 11 0e 11 0f 58 13 0e 00 11 0e 11 0c fe 04 13 13 11 13 2d c9 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_BAT_NjRat_BAA_MTB_2{
	meta:
		description = "Trojan:BAT/NjRat.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 25 00 00 0a 0c 08 07 ?? ?? 00 00 0a 17 73 27 00 00 0a 0d 09 02 16 02 8e b7 ?? ?? 00 00 0a 09 ?? ?? 00 00 0a de 0a 09 2c 06 09 ?? ?? 00 00 0a dc 08 ?? ?? 00 00 0a 0a de 18 de 0a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}