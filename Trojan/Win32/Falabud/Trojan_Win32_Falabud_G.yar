
rule Trojan_Win32_Falabud_G{
	meta:
		description = "Trojan:Win32/Falabud.G,SIGNATURE_TYPE_CMDHSTR_EXT,46 00 46 00 07 00 00 0a 00 "
		
	strings :
		$a_00_0 = {63 00 6d 00 64 00 20 00 2f 00 63 00 } //0a 00  cmd /c
		$a_00_1 = {66 00 69 00 6e 00 64 00 73 00 74 00 72 00 } //0a 00  findstr
		$a_00_2 = {77 00 6d 00 69 00 63 00 } //0a 00  wmic
		$a_00_3 = {68 00 6f 00 74 00 66 00 69 00 78 00 69 00 64 00 } //0a 00  hotfixid
		$a_00_4 = {6b 00 62 00 34 00 34 00 39 00 39 00 31 00 37 00 35 00 } //0a 00  kb4499175
		$a_00_5 = {72 00 64 00 74 00 6f 00 67 00 67 00 6c 00 65 00 } //0a 00  rdtoggle
		$a_00_6 = {53 00 65 00 74 00 41 00 6c 00 6c 00 6f 00 77 00 54 00 53 00 43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 69 00 6f 00 6e 00 73 00 } //00 00  SetAllowTSConnections
	condition:
		any of ($a_*)
 
}