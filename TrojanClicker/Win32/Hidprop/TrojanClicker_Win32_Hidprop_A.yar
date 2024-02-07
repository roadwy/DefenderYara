
rule TrojanClicker_Win32_Hidprop_A{
	meta:
		description = "TrojanClicker:Win32/Hidprop.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 00 69 00 64 00 65 00 72 00 5c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 31 00 2e 00 76 00 62 00 70 00 } //01 00  hider\Project1.vbp
		$a_01_1 = {79 00 6f 00 75 00 74 00 75 00 62 00 65 00 2f 00 69 00 6e 00 64 00 65 00 78 00 2e 00 70 00 68 00 70 00 3f 00 61 00 63 00 74 00 3d 00 63 00 6f 00 6e 00 73 00 6f 00 6c 00 65 00 26 00 70 00 68 00 6f 00 6e 00 65 00 3d 00 } //01 00  youtube/index.php?act=console&phone=
		$a_01_2 = {33 00 37 00 2e 00 35 00 39 00 2e 00 32 00 34 00 36 00 2e 00 31 00 34 00 31 00 } //01 00  37.59.246.141
		$a_01_3 = {74 00 73 00 6b 00 69 00 6c 00 6c 00 20 00 69 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 } //00 00  tskill iexplore
	condition:
		any of ($a_*)
 
}