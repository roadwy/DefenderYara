
rule Trojan_Win32_LokiBot_RPH_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.RPH!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 10 89 38 0f b6 d2 89 16 8b 00 03 c2 23 c1 8a 04 85 } //00 00 
	condition:
		any of ($a_*)
 
}