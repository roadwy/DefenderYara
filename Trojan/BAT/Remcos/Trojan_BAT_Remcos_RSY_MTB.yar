
rule Trojan_BAT_Remcos_RSY_MTB{
	meta:
		description = "Trojan:BAT/Remcos.RSY!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {28 0f 00 00 06 28 01 00 00 2b 28 02 00 00 2b 0a de 03 26 de ea } //00 00 
	condition:
		any of ($a_*)
 
}