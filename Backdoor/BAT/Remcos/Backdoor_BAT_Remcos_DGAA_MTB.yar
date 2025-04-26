
rule Backdoor_BAT_Remcos_DGAA_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.DGAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 05 1a 8d 18 00 00 01 25 16 11 04 a2 25 17 7e 16 00 00 0a a2 25 18 07 a2 25 19 17 8c 04 00 00 01 a2 13 06 11 05 08 6f ?? 00 00 0a 09 20 00 01 00 00 14 14 11 06 74 01 00 00 1b 6f ?? 00 00 0a 26 2a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}