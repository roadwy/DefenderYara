
rule Trojan_BAT_Disdroth_PTIT_MTB{
	meta:
		description = "Trojan:BAT/Disdroth.PTIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 06 11 06 28 ?? 00 00 06 06 28 ?? 00 00 0a 2c 06 06 28 ?? 00 00 0a 08 06 28 ?? 00 00 0a de 03 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}