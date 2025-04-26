
rule Backdoor_BAT_Androm_SL_MTB{
	meta:
		description = "Backdoor:BAT/Androm.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 02 06 5a 03 5d 17 fe 01 0b 07 39 08 00 00 00 00 06 0c 38 18 00 00 00 00 06 17 58 0a 06 03 fe 04 0d 09 2d db } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}