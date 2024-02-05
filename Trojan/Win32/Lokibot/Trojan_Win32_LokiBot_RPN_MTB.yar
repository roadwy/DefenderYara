
rule Trojan_Win32_LokiBot_RPN_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.RPN!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {0b c1 88 45 ff 0f b6 55 ff 2b 55 f8 88 55 ff 8b 45 f8 8a 4d ff 88 88 } //00 00 
	condition:
		any of ($a_*)
 
}