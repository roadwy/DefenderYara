
rule Trojan_Win32_LokiBot_RPM_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.RPM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {fe 0c 07 8b 0c 24 80 34 01 90 01 01 8b 0c 24 80 04 01 90 01 01 8b 0c 24 80 04 01 90 01 01 8b 0c 24 80 34 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}