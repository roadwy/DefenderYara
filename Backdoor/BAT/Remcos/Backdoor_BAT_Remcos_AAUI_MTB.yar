
rule Backdoor_BAT_Remcos_AAUI_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.AAUI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 08 03 8e 69 5d 7e 90 01 01 00 00 04 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 90 01 02 00 06 03 08 20 8e 10 00 00 58 20 8d 10 00 00 59 03 8e 69 5d 91 59 20 fe 00 00 00 58 18 58 20 00 01 00 00 5d d2 9c 08 17 58 0c 08 6a 03 8e 69 17 59 6a 06 17 58 6e 5a 31 aa 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}