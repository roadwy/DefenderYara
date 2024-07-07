
rule Trojan_BAT_Zusy_PTCQ_MTB{
	meta:
		description = "Trojan:BAT/Zusy.PTCQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 6f 32 00 00 06 6f 6a 00 00 0a 00 02 72 df 00 00 70 6f 60 00 00 0a 00 02 72 eb 00 00 70 6f 6b 00 00 0a 00 02 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}