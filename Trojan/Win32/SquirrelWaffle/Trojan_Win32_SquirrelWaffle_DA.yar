
rule Trojan_Win32_SquirrelWaffle_DA{
	meta:
		description = "Trojan:Win32/SquirrelWaffle.DA,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 63 74 63 61 75 73 65 } //01 00  Actcause
		$a_01_1 = {42 72 65 61 6b 62 6f 78 } //01 00  Breakbox
		$a_01_2 = {43 61 75 73 65 53 65 61 74 } //01 00  CauseSeat
		$a_01_3 = {44 75 72 69 6e 67 77 65 69 67 68 74 } //01 00  Duringweight
		$a_01_4 = {45 71 75 61 6c 63 72 79 } //00 00  Equalcry
		$a_00_5 = {5d 04 00 } //00 ee 
	condition:
		any of ($a_*)
 
}