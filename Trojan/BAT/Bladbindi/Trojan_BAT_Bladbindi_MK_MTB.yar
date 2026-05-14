
rule Trojan_BAT_Bladbindi_MK_MTB{
	meta:
		description = "Trojan:BAT/Bladbindi.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 02 00 00 "
		
	strings :
		$a_01_0 = {14 0c 07 b5 1f 64 28 29 00 00 0a 0d 12 03 1f 64 12 02 1f 64 28 18 00 00 06 2c 04 17 0a de 27 07 17 d6 0b 07 1a 31 d9 } //25
		$a_01_1 = {0c 07 14 fe 01 08 14 fe 01 5f 2c 04 17 0a 2b 0c 07 2d 04 16 0a 2b 05 08 2d b7 } //10
	condition:
		((#a_01_0  & 1)*25+(#a_01_1  & 1)*10) >=35
 
}