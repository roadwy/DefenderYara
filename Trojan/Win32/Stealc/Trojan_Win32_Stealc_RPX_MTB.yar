
rule Trojan_Win32_Stealc_RPX_MTB{
	meta:
		description = "Trojan:Win32/Stealc.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 dc 01 45 fc 8b 4d f8 8d 04 13 d3 ea 89 45 f4 03 55 d4 8b 45 f4 31 45 fc 31 55 fc 8b 45 fc 29 45 f0 } //00 00 
	condition:
		any of ($a_*)
 
}