
rule Trojan_BAT_Cerbu_AMA_MTB{
	meta:
		description = "Trojan:BAT/Cerbu.AMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 5b 26 11 [0-14] 03 12 ?? 28 ?? 00 00 0a 28 ?? 00 00 0a 8f ?? 00 00 01 25 71 ?? 00 00 01 06 12 ?? 28 ?? 00 00 0a 28 ?? 00 00 0a 91 61 d2 81 ?? 00 00 01 de } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}