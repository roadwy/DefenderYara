
rule Trojan_Win32_LokiBot_RPO_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.RPO!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {88 45 ff 0f b6 4d ff 83 e9 79 88 4d ff 8b 55 f8 8a 45 ff 88 82 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_LokiBot_RPO_MTB_2{
	meta:
		description = "Trojan:Win32/LokiBot.RPO!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 f8 03 45 fc 88 10 8b 4d f8 03 4d fc 8a 11 80 ea 01 8b 45 f8 03 45 fc 88 10 e9 } //00 00 
	condition:
		any of ($a_*)
 
}