
rule Trojan_BAT_Razy_PPD_MTB{
	meta:
		description = "Trojan:BAT/Razy.PPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 63 00 00 0a 0a 06 72 0d 02 00 70 72 d9 01 00 70 28 ?? 00 00 06 72 b8 02 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 2a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}