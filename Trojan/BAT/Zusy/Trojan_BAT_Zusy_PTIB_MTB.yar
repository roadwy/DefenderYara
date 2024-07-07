
rule Trojan_BAT_Zusy_PTIB_MTB{
	meta:
		description = "Trojan:BAT/Zusy.PTIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 45 00 00 70 28 90 01 01 00 00 0a 6f 12 00 00 0a 6f 12 00 00 0a 6f 13 00 00 0a 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}