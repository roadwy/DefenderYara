
rule Backdoor_BAT_Androm_AFLA_MTB{
	meta:
		description = "Backdoor:BAT/Androm.AFLA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 06 38 1b 00 00 00 11 05 11 06 06 11 06 91 72 ?? 00 00 70 28 ?? 00 00 0a 59 d2 9c 11 06 17 58 13 06 11 06 06 8e 69 32 de } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}