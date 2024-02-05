
rule Trojan_BAT_Swotter_FAC_MTB{
	meta:
		description = "Trojan:BAT/Swotter.FAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 04 00 00 0a 00 "
		
	strings :
		$a_00_0 = {06 17 d6 0a 09 17 d6 0d 09 20 ff c9 00 00 31 c8 } //05 00 
		$a_80_1 = {49 44 4d 2e 49 55 65 6c 70 6d 69 53 } //IDM.IUelpmiS  05 00 
		$a_80_2 = {52 4d 53 70 6c 61 73 68 } //RMSplash  04 00 
		$a_80_3 = {5c 52 6f 73 74 65 72 4c 6f 61 64 2e 74 78 74 } //\RosterLoad.txt  00 00 
	condition:
		any of ($a_*)
 
}