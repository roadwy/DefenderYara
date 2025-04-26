
rule Trojan_BAT_Starter_ASR_MTB{
	meta:
		description = "Trojan:BAT/Starter.ASR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 01 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 26 de 0c 28 ?? 00 00 0a 28 ?? 00 00 0a de 00 28 ?? 00 00 0a 72 43 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 26 de 0c } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}