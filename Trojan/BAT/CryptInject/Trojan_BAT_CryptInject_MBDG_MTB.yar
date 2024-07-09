
rule Trojan_BAT_CryptInject_MBDG_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.MBDG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 07 8e 69 8c ?? 00 00 01 14 14 17 8c ?? 00 00 01 28 ?? 00 00 06 28 ?? 00 00 0a 28 ?? 00 00 0a 13 0a 11 0a 11 05 5f 13 0b 07 11 04 8c ?? 00 00 01 07 8e 69 8c ?? 00 00 01 14 14 17 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}