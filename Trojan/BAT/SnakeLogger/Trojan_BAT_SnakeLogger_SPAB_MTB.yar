
rule Trojan_BAT_SnakeLogger_SPAB_MTB{
	meta:
		description = "Trojan:BAT/SnakeLogger.SPAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 11 05 07 11 05 9a 1f 10 28 90 01 03 0a d2 9c 00 11 05 17 58 13 05 11 05 07 8e 69 fe 04 13 06 11 06 2d db 90 00 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}