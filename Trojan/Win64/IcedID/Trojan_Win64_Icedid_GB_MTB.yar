
rule Trojan_Win64_Icedid_GB_MTB{
	meta:
		description = "Trojan:Win64/Icedid.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {44 31 f3 88 5c 24 90 01 01 c7 44 24 90 02 05 8a 54 24 90 01 01 80 ea 90 01 01 80 c2 90 01 01 80 c2 90 01 01 88 54 24 90 01 01 c7 44 24 90 02 05 8a 54 24 90 01 01 48 8b 4c 24 90 01 01 88 11 c7 44 24 90 02 05 48 8b 4c 24 90 01 01 48 81 c1 01 00 00 00 48 89 4c 24 90 01 01 c7 44 24 90 02 05 44 8b 5c 24 90 01 01 83 e8 ff 41 29 c3 44 89 5c 24 90 01 01 41 83 fb 00 0f 84 90 02 04 c7 44 24 90 02 05 e9 90 00 } //01 00 
		$a_80_1 = {50 6c 75 67 69 6e 49 6e 69 74 } //PluginInit  00 00 
	condition:
		any of ($a_*)
 
}