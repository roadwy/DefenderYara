
rule Trojan_Win32_TurtleLoader_CS_dha{
	meta:
		description = "Trojan:Win32/TurtleLoader.CS!dha,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {0c 4b 8b 58 1c 01 d3 8b 04 8b 01 d0 89 44 24 24 5b 5b 61 59 5a 51 ff e0 58 5f 5a 8b 12 eb 86 5d 68 6e 65 74 00 68 77 69 6e 69 54 68 4c 77 26 07 } //00 00 
	condition:
		any of ($a_*)
 
}