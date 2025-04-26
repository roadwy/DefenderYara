
rule Trojan_BAT_SnakeKeyLogger_RDCL_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDCL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 04 07 8e 69 5d 91 61 d2 9c 00 11 04 17 58 13 04 11 04 } //2
		$a_01_1 = {8e 69 5d 91 61 d2 9c 00 11 06 17 58 13 06 11 06 } //3
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*3) >=5
 
}