
rule Trojan_BAT_Injuke_AATK_MTB{
	meta:
		description = "Trojan:BAT/Injuke.AATK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 05 2b 23 09 11 05 16 6f ?? 00 00 0a 13 06 12 06 28 ?? 00 00 0a 13 07 11 04 11 07 6f ?? 00 00 0a 11 05 17 58 13 05 11 05 09 6f ?? 00 00 0a 32 d3 11 04 6f ?? 00 00 0a 13 08 de 0a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}