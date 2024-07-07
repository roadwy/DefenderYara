
rule Trojan_BAT_Darkcomet_AVY_MTB{
	meta:
		description = "Trojan:BAT/Darkcomet.AVY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {07 11 08 11 05 20 00 01 00 00 5d b4 9c 07 11 08 17 d6 11 07 20 00 01 00 00 5d b4 9c 00 11 08 18 d6 13 08 11 08 11 0c 13 0e 11 0e 31 81 } //2
		$a_01_1 = {6a 00 61 00 63 00 71 00 75 00 65 00 73 00 } //1 jacques
		$a_01_2 = {75 00 6e 00 6f 00 72 00 6f 00 } //1 unoro
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}