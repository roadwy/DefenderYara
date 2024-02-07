
rule Trojan_Win32_Babar_SPS_MTB{
	meta:
		description = "Trojan:Win32/Babar.SPS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 4d d4 8a 91 90 01 04 88 55 d3 0f b6 45 d3 03 45 d4 88 45 d3 0f b6 4d d3 f7 d1 88 4d d3 0f b6 55 d3 03 55 d4 88 55 d3 90 00 } //01 00 
		$a_01_1 = {6f 6f 6d 63 65 62 67 79 6a 70 62 77 6d 67 } //00 00  oomcebgyjpbwmg
	condition:
		any of ($a_*)
 
}