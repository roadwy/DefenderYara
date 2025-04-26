
rule Trojan_Win32_LokiBot_RPJ_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.RPJ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 02 83 45 fc 01 73 05 e8 a6 b5 fa ff 90 90 90 ff 45 f8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}