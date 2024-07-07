
rule Trojan_BAT_Taskun_FAI_MTB{
	meta:
		description = "Trojan:BAT/Taskun.FAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0c 16 0b 2b 19 08 06 07 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 07 18 58 0b 07 06 6f 90 01 01 00 00 0a fe 04 13 08 11 08 2d d8 90 00 } //3
		$a_01_1 = {4b 6f 6c 6b 6f 5f 69 5f 6b 72 7a 79 7a 79 6b 2e 52 65 73 6f 75 72 63 65 58 } //2 Kolko_i_krzyzyk.ResourceX
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}