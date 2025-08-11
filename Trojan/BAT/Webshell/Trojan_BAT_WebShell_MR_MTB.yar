
rule Trojan_BAT_WebShell_MR_MTB{
	meta:
		description = "Trojan:BAT/WebShell.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {08 09 94 0a 00 06 03 fe 01 16 fe 01 13 04 11 04 2d 04 17 0b de 15 00 09 17 58 0d } //5
		$a_01_1 = {0a 06 16 1b 9e 06 17 17 9e 06 18 1a 9e 06 } //10
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*10) >=15
 
}