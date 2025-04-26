
rule Trojan_BAT_SnakeLogger_BE_MTB{
	meta:
		description = "Trojan:BAT/SnakeLogger.BE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 0c 2b 15 00 02 08 03 08 91 05 08 06 8e 69 5d 91 61 d2 9c 00 08 17 58 0c 08 03 8e 69 fe 04 0d 09 2d } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}