
rule Trojan_BAT_Remcos_AMBG_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AMBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {70 18 14 6f ?? 00 00 0a 72 ?? 02 00 70 18 14 6f ?? 00 00 0a 72 ?? 02 00 70 18 17 8d ?? 01 00 01 25 16 7e ?? 00 00 04 6f ?? 00 00 0a a2 6f ?? 00 00 0a 72 ?? 02 00 70 18 14 6f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}