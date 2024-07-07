
rule Trojan_BAT_Marsilia_PTFA_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.PTFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 a2 07 00 70 0a 06 28 90 01 01 01 00 0a 0b 28 90 01 01 01 00 0a 25 26 07 16 07 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}