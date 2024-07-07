
rule Backdoor_BAT_Remcos_ST_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.ST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 08 17 58 13 06 07 08 07 08 91 28 90 01 03 06 08 1f 16 5d 91 61 07 11 06 07 8e 69 5d 91 59 20 00 01 00 00 58 d2 9c 08 17 58 0c 00 08 09 fe 04 13 07 11 07 2d ca 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}