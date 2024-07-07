
rule Trojan_BAT_SnakeLogger_NSS_MTB{
	meta:
		description = "Trojan:BAT/SnakeLogger.NSS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 82 01 00 06 72 90 01 03 70 7e 90 01 03 04 6f 90 01 03 0a 13 00 20 90 01 03 00 28 90 01 03 06 39 90 01 03 ff 90 00 } //5
		$a_01_1 = {52 48 61 6c 48 } //1 RHalH
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}