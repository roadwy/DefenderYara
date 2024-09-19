
rule Trojan_BAT_Remcos_SAA_MTB{
	meta:
		description = "Trojan:BAT/Remcos.SAA!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 08 28 0e 00 00 06 0d 7e 05 00 00 04 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}