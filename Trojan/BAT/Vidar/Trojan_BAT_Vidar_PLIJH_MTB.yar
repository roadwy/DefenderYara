
rule Trojan_BAT_Vidar_PLIJH_MTB{
	meta:
		description = "Trojan:BAT/Vidar.PLIJH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 1f 09 0b 05 04 07 5d 9a 28 ?? 00 00 0a 03 28 ?? 00 00 06 28 ?? 00 00 0a 0a 2b 00 06 2a } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}