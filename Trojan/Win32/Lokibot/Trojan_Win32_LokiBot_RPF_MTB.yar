
rule Trojan_Win32_LokiBot_RPF_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.RPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {88 45 ff 0f b6 45 ff 33 45 f8 88 45 ff 0f b6 45 ff 2b 45 f8 88 45 ff 8b 45 f4 03 45 f8 8a 4d ff 88 08 e9 } //00 00 
	condition:
		any of ($a_*)
 
}