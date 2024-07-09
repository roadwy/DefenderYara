
rule Trojan_BAT_Remcos_KAAM_MTB{
	meta:
		description = "Trojan:BAT/Remcos.KAAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 25 17 6f ?? 00 00 0a 25 18 6f ?? 00 00 0a 25 03 6f ?? 00 00 0a 25 04 6f ?? 00 00 0a 6f ?? 00 00 0a 02 16 02 8e 69 6f ?? 00 00 0a 10 00 02 2a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}