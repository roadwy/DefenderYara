
rule Trojan_BAT_Zusy_MKD_MTB{
	meta:
		description = "Trojan:BAT/Zusy.MKD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 02 00 00 "
		
	strings :
		$a_01_0 = {6f 25 00 00 0a 06 20 00 00 10 00 6f 26 00 00 0a 06 20 00 00 10 00 6f 27 00 00 0a 06 16 6f 28 00 00 0a 02 28 29 00 00 0a 03 73 2a 00 00 0a } //20
		$a_01_1 = {09 fe 06 19 00 00 06 73 1b 00 00 0a 73 1c 00 00 0a a2 07 08 9a 17 6f 21 00 00 0a 07 08 9a 1a 6f 22 00 00 0a 07 08 9a 6f 1d 00 00 0a 08 17 58 0c 08 06 32 b5 } //15
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*15) >=35
 
}