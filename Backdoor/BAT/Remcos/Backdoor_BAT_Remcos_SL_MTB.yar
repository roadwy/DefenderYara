
rule Backdoor_BAT_Remcos_SL_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 09 6f 0f 00 00 0a 13 04 06 07 11 04 03 58 d1 9d 07 17 58 0b 09 17 58 0d 09 08 6f 0e 00 00 0a 32 de } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}