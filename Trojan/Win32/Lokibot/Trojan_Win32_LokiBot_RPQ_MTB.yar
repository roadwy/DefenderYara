
rule Trojan_Win32_LokiBot_RPQ_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.RPQ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 4d ff 0f b6 55 ff 81 f2 b9 00 00 00 88 55 ff 8b 45 f8 8a 4d ff 88 88 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}