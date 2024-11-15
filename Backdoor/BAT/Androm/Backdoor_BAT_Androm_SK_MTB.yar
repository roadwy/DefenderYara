
rule Backdoor_BAT_Androm_SK_MTB{
	meta:
		description = "Backdoor:BAT/Androm.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 08 6f 5a 00 00 0a 11 07 18 6f 5b 00 00 0a 1f 10 28 5c 00 00 0a 28 5d 00 00 0a 16 91 13 08 09 11 08 6f 5e 00 00 0a 00 00 11 07 18 58 13 07 11 07 08 6f 5a 00 00 0a 6f 56 00 00 0a fe 04 13 09 11 09 2d bc } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}