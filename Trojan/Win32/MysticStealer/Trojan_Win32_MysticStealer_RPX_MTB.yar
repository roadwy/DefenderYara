
rule Trojan_Win32_MysticStealer_RPX_MTB{
	meta:
		description = "Trojan:Win32/MysticStealer.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {ff d3 80 04 3e 1c ff d3 80 04 3e fa ff d3 80 34 3e 4b ff d3 80 04 3e 7a ff d3 80 04 3e c0 ff d3 80 04 3e 6e ff d3 } //00 00 
	condition:
		any of ($a_*)
 
}