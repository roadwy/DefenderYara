
rule Backdoor_BAT_Androm_KAAC_MTB{
	meta:
		description = "Backdoor:BAT/Androm.KAAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 11 04 11 08 58 11 07 11 09 58 6f 90 01 01 00 00 0a 13 0a 12 0a 28 90 01 01 00 00 0a 13 0b 08 07 11 0b 9c 07 17 58 0b 11 09 17 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}