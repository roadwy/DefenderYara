
rule Trojan_BAT_SnakeKeyLogger_AMAN_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.AMAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8e 69 5d 91 13 [0-14] 61 [0-32] 59 20 00 01 00 00 58 20 ff 00 00 00 5f d2 9c 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}