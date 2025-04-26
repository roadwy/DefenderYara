
rule Backdoor_BAT_Androm_KAAB_MTB{
	meta:
		description = "Backdoor:BAT/Androm.KAAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 08 11 04 07 11 04 18 5a 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a d2 9c 00 11 04 17 58 13 04 11 04 08 8e 69 fe 04 13 05 11 05 2d d4 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}