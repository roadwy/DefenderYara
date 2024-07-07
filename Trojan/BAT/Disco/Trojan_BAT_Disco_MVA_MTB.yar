
rule Trojan_BAT_Disco_MVA_MTB{
	meta:
		description = "Trojan:BAT/Disco.MVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 28 1a 00 00 0a 72 7d 00 00 70 72 8b 00 00 70 28 0a 00 00 06 28 1b 00 00 0a 1b 28 0e 00 00 06 14 16 28 1c 00 00 0a 0a de 05 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}