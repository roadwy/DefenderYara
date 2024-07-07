
rule Trojan_Win32_LokiBot_RPL_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.RPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {31 c0 fe 0c 07 8b 0c 24 fe 0c 01 8b 0c 24 fe 04 01 8b 0c 24 80 04 01 90 01 01 8b 0c 24 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}