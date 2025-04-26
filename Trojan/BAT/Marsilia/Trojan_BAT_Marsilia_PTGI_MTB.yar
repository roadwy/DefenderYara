
rule Trojan_BAT_Marsilia_PTGI_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.PTGI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {7e 01 00 00 04 72 71 00 00 70 73 12 00 00 0a 28 ?? 00 00 0a 72 c5 00 00 70 28 ?? 00 00 0a 6f 15 00 00 0a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}