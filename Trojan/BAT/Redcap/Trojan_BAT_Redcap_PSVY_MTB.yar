
rule Trojan_BAT_Redcap_PSVY_MTB{
	meta:
		description = "Trojan:BAT/Redcap.PSVY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 16 28 89 00 00 0a 0a 06 28 ?? 00 00 0a 00 20 00 e1 f5 05 6a 28 ?? 00 00 0a 00 28 ?? 00 00 0a 00 20 e8 03 00 00 28 ?? 00 00 0a 00 00 de 05 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}