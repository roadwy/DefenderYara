
rule Trojan_BAT_Heracles_PTDU_MTB{
	meta:
		description = "Trojan:BAT/Heracles.PTDU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {6f 17 00 00 0a dc 28 90 01 01 00 00 0a 08 6f 39 00 00 0a 6f 3c 00 00 0a 13 04 de 14 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}