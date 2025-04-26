
rule Trojan_BAT_Injuke_TKAA_MTB{
	meta:
		description = "Trojan:BAT/Injuke.TKAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 16 0c 38 19 00 00 00 06 07 08 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 6f ?? 00 00 0a 08 18 58 0c 08 07 6f ?? 00 00 0a 32 de } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}