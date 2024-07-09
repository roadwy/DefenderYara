
rule Trojan_BAT_Injuke_ASCL_MTB{
	meta:
		description = "Trojan:BAT/Injuke.ASCL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 06 11 05 8e 69 17 da 13 1e 16 13 1f 2b 1d 11 06 11 1f 11 05 11 1f 9a 1f 10 28 ?? 00 00 0a 86 6f ?? 00 00 0a 00 11 1f 17 d6 13 1f 11 1f 11 1e 31 dd } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}