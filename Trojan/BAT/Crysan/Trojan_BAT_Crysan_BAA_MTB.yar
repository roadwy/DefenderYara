
rule Trojan_BAT_Crysan_BAA_MTB{
	meta:
		description = "Trojan:BAT/Crysan.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 04 05 06 58 0e 04 06 59 ?? ?? ?? ?? ?? 0b 07 3a 0b 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 7a 06 07 58 0a 06 0e 04 32 d7 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_BAT_Crysan_BAA_MTB_2{
	meta:
		description = "Trojan:BAT/Crysan.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {6f 11 00 00 0a 0c 08 6f 12 00 00 0a 0d 09 02 16 02 8e 69 6f 13 00 00 0a 13 04 dd 1a 00 00 00 09 39 06 00 00 00 09 6f 0b 00 00 0a dc 08 39 06 00 00 00 08 6f 0b 00 00 0a dc } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}