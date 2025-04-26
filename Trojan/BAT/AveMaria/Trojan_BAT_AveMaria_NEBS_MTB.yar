
rule Trojan_BAT_AveMaria_NEBS_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEBS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 28 bb 01 00 06 72 05 00 00 70 28 09 00 00 06 0a 06 28 18 00 00 0a } //10
		$a_01_1 = {53 00 41 00 46 00 53 00 41 00 46 00 53 00 53 00 41 00 46 00 53 00 41 00 46 00 53 00 46 00 53 00 41 00 46 00 53 00 41 00 46 00 53 00 41 00 } //5 SAFSAFSSAFSAFSFSAFSAFSA
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}