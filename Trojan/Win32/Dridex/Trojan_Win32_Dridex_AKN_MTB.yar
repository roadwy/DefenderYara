
rule Trojan_Win32_Dridex_AKN_MTB{
	meta:
		description = "Trojan:Win32/Dridex.AKN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 06 00 00 0a 00 "
		
	strings :
		$a_00_0 = {2b c1 2d 75 6a 00 00 0f b7 c0 8d b8 db 3b 01 00 03 fe 83 } //03 00 
		$a_80_1 = {48 75 6e 74 72 6f 6f 6d } //Huntroom  03 00 
		$a_80_2 = {49 6e 73 65 63 74 67 6f 74 } //Insectgot  03 00 
		$a_80_3 = {50 75 73 68 73 74 72 65 74 63 68 } //Pushstretch  03 00 
		$a_80_4 = {52 65 64 73 79 6c 6c 61 62 6c 65 } //Redsyllable  03 00 
		$a_80_5 = {51 75 61 72 74 5c 74 61 62 6c 65 2e 70 64 62 } //Quart\table.pdb  00 00 
	condition:
		any of ($a_*)
 
}