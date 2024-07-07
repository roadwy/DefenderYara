
rule Backdoor_BAT_AsyncRAT_MK_MTB{
	meta:
		description = "Backdoor:BAT/AsyncRAT.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {91 07 08 07 8e 69 5d 91 61 28 90 01 03 06 03 08 1b 58 19 59 17 59 03 8e 69 5d 91 59 20 90 01 03 00 58 19 59 17 58 20 00 01 00 00 5d d2 9c 08 17 58 16 2d 05 19 2d 39 26 08 6a 03 8e 69 17 59 6a 06 17 58 6e 5a 19 2c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}