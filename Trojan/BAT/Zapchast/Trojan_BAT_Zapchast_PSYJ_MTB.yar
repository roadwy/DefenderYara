
rule Trojan_BAT_Zapchast_PSYJ_MTB{
	meta:
		description = "Trojan:BAT/Zapchast.PSYJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {6f 35 01 00 0a 17 73 66 01 00 0a 0c 08 02 16 02 8e 69 6f 85 01 00 0a 08 6f 9b 00 00 0a 06 6f 8e 00 00 0a 0d 09 2a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}