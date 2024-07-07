
rule Trojan_BAT_Heracles_PTFD_MTB{
	meta:
		description = "Trojan:BAT/Heracles.PTFD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 2e 07 07 02 28 90 01 01 03 00 0a 07 28 90 01 01 3a 00 06 7e a2 00 00 0a 28 90 01 01 03 00 0a 0a de 05 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}