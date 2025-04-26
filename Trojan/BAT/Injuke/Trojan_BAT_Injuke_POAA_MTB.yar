
rule Trojan_BAT_Injuke_POAA_MTB{
	meta:
		description = "Trojan:BAT/Injuke.POAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 72 f1 00 00 70 18 18 8d 10 00 00 01 25 16 7e ?? 00 00 04 a2 25 17 7e ?? 00 00 04 a2 28 ?? 00 00 0a 74 ?? 00 00 01 0a 06 02 16 02 8e 69 6f ?? 00 00 0a 0b de 0a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}