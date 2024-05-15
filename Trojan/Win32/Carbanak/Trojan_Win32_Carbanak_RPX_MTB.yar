
rule Trojan_Win32_Carbanak_RPX_MTB{
	meta:
		description = "Trojan:Win32/Carbanak.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {2b 45 f8 3b c3 7d 04 2b d3 03 c2 8b 5d e4 8b 55 f4 88 04 1f 8b 45 f0 47 4a 89 55 f4 46 3b f8 7c } //00 00 
	condition:
		any of ($a_*)
 
}