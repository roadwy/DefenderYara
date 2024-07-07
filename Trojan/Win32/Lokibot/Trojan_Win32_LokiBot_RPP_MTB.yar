
rule Trojan_Win32_LokiBot_RPP_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.RPP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 c8 f7 e3 d1 ea 83 e2 fc 8d 04 52 f7 d8 8b 14 24 8a 04 07 30 04 0a 41 47 39 ce 75 e3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_LokiBot_RPP_MTB_2{
	meta:
		description = "Trojan:Win32/LokiBot.RPP!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 4d ff 0f b6 55 ff 81 f2 8d 00 00 00 88 55 ff 8b 45 f8 8a 4d ff 88 88 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}