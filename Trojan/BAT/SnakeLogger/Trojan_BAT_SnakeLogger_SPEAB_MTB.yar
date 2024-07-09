
rule Trojan_BAT_SnakeLogger_SPEAB_MTB{
	meta:
		description = "Trojan:BAT/SnakeLogger.SPEAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 11 07 08 11 07 9a 1f 10 28 ?? ?? ?? 0a d2 9c 00 11 07 17 58 13 07 11 07 08 8e 69 fe 04 13 08 11 08 2d db } //4
		$a_01_1 = {67 65 71 2d 63 2f 70 } //1 geq-c/p
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}