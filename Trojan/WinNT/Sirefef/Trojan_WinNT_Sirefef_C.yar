
rule Trojan_WinNT_Sirefef_C{
	meta:
		description = "Trojan:WinNT/Sirefef.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 40 08 25 ff ff ff 00 bb 22 00 00 c0 3d 00 01 00 00 } //01 00 
		$a_01_1 = {68 7e 44 c5 a7 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_WinNT_Sirefef_C_2{
	meta:
		description = "Trojan:WinNT/Sirefef.C,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 40 08 25 ff ff ff 00 bb 22 00 00 c0 3d 00 01 00 00 } //01 00 
		$a_01_1 = {68 7e 44 c5 a7 } //00 00 
	condition:
		any of ($a_*)
 
}