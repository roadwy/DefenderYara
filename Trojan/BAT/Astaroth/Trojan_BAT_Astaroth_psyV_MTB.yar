
rule Trojan_BAT_Astaroth_psyV_MTB{
	meta:
		description = "Trojan:BAT/Astaroth.psyV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 1d 00 00 0a 72 01 00 00 70 28 1e 00 00 0a 28 1f 00 00 0a 26 de 0c 28 20 00 00 0a 28 21 00 00 0a de 00 28 1d 00 00 0a 72 63 00 00 70 28 1e 00 00 0a 28 1f 00 00 0a 26 de 0c } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}