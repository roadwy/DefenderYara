
rule Backdoor_BAT_QuasarRAT_C_MTB{
	meta:
		description = "Backdoor:BAT/QuasarRAT.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 08 06 8e 69 5d 06 08 06 8e 69 5d 91 07 08 1f 90 01 01 5d 91 61 28 90 01 01 00 00 0a 06 08 17 58 06 8e 69 5d 91 28 90 01 01 00 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 00 08 15 58 90 00 } //2
		$a_03_1 = {00 00 01 25 16 1f 90 01 01 9d 6f 90 09 05 00 00 04 17 8d 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}