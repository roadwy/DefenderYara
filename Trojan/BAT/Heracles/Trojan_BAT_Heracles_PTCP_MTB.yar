
rule Trojan_BAT_Heracles_PTCP_MTB{
	meta:
		description = "Trojan:BAT/Heracles.PTCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 72 d9 01 00 70 28 ?? 00 00 0a 26 72 15 02 00 70 28 ?? 00 00 0a 26 2a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}