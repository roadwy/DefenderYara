
rule Trojan_BAT_CyberGate_KAA_MTB{
	meta:
		description = "Trojan:BAT/CyberGate.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 09 91 07 1f 1f 5f 62 09 28 ?? 00 00 06 08 58 13 04 06 08 06 08 91 11 04 28 ?? 00 00 06 d2 9c 09 17 58 0d 09 03 8e 69 32 d6 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}