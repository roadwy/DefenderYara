
rule Trojan_BAT_Crysan_SPQI_MTB{
	meta:
		description = "Trojan:BAT/Crysan.SPQI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {38 22 00 00 00 00 28 ?? ?? ?? 06 16 fe 01 0d 09 39 06 00 00 00 28 ?? ?? ?? 06 00 20 ?? ?? ?? 00 28 ?? ?? ?? 0a 00 00 17 13 04 38 d6 ff ff ff } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}