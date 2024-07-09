
rule Trojan_BAT_Convagent_PTCF_MTB{
	meta:
		description = "Trojan:BAT/Convagent.PTCF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 7b 04 00 00 04 6f 36 00 00 0a 6f 28 00 00 0a 0a 02 72 f9 00 00 70 06 72 19 01 00 70 28 ?? 00 00 0a 28 ?? 00 00 06 00 2a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}