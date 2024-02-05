
rule Trojan_Win32_RemcosRAT_RPF_MTB{
	meta:
		description = "Trojan:Win32/RemcosRAT.RPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 40 3c 99 03 04 24 13 54 24 04 83 c4 08 89 07 49 89 c2 6a 01 68 00 20 00 00 8b 07 8b 40 50 50 6a 00 } //00 00 
	condition:
		any of ($a_*)
 
}