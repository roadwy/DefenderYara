
rule Trojan_BAT_SnakeKeyLogger_AMF_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.AMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 02 06 07 6f ?? 00 00 0a 0c 03 6f ?? 00 00 0a 19 58 04 fe 02 16 fe 01 0d } //3
		$a_03_1 = {02 0f 01 28 ?? 00 00 0a 6f ?? 00 00 0a 00 02 0f 01 28 ?? 00 00 0a 6f } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}