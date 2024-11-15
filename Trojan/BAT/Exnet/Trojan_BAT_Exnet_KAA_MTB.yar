
rule Trojan_BAT_Exnet_KAA_MTB{
	meta:
		description = "Trojan:BAT/Exnet.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 08 02 07 17 28 ?? 00 00 0a 28 ?? 00 00 0a 61 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0a 07 17 58 b5 0b 07 09 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}