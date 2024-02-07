
rule Trojan_Win32_Qbot_RPF_MTB{
	meta:
		description = "Trojan:Win32/Qbot.RPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0d 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 6c 61 6e 5f 53 6f 6f 6e } //01 00  Plan_Soon
		$a_01_1 = {53 68 61 70 65 5f 45 6e 74 65 72 } //01 00  Shape_Enter
		$a_01_2 = {63 65 6e 74 2e 70 64 62 } //01 00  cent.pdb
		$a_01_3 = {63 65 6e 74 2e 64 6c 6c } //01 00  cent.dll
		$a_01_4 = {41 72 72 61 6e 67 65 73 75 72 70 72 69 73 65 } //01 00  Arrangesurprise
		$a_01_5 = {43 6f 75 6e 74 } //01 00  Count
		$a_01_6 = {44 72 61 77 70 61 70 65 72 } //01 00  Drawpaper
		$a_01_7 = {46 61 76 6f 72 73 68 69 70 } //01 00  Favorship
		$a_01_8 = {47 61 76 65 63 68 69 63 6b } //01 00  Gavechick
		$a_01_9 = {48 69 73 74 6f 72 79 4d 6f 6d 65 6e 74 } //01 00  HistoryMoment
		$a_01_10 = {48 69 74 61 6e 69 6d 61 6c } //01 00  Hitanimal
		$a_01_11 = {53 74 61 6e 64 74 65 72 6d } //01 00  Standterm
		$a_01_12 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 45 78 } //00 00  VirtualProtectEx
	condition:
		any of ($a_*)
 
}