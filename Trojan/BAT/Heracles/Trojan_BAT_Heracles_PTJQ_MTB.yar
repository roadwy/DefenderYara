
rule Trojan_BAT_Heracles_PTJQ_MTB{
	meta:
		description = "Trojan:BAT/Heracles.PTJQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {6f 9c 00 00 0a 17 59 28 ?? 00 00 0a 16 7e 73 00 00 04 02 1a 28 ?? 00 00 0a 11 05 0d } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}