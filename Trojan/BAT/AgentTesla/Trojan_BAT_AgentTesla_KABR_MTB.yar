
rule Trojan_BAT_AgentTesla_KABR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.KABR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 07 08 18 5b 02 08 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 9c 00 08 18 58 0c 08 06 fe 04 0d 09 2d de } //5
		$a_01_1 = {30 00 36 00 32 00 42 00 46 00 36 00 32 00 38 00 37 00 32 00 } //5 062BF62872
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}