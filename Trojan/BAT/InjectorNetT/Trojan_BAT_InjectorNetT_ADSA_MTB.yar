
rule Trojan_BAT_InjectorNetT_ADSA_MTB{
	meta:
		description = "Trojan:BAT/InjectorNetT.ADSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 94 07 00 70 38 77 00 00 00 38 7c 00 00 00 72 c6 07 00 70 38 78 00 00 00 38 7d 00 00 00 16 2d ee 38 7b 00 00 00 38 80 00 00 00 08 06 6f ?? ?? 00 0a 08 07 6f ?? ?? 00 0a 08 6f ?? ?? 00 0a 0d 2b 10 2b 11 16 2b 11 8e 69 6f ?? ?? 00 0a 13 04 de 26 09 2b ed 02 2b ec 02 2b ec } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}