
rule Trojan_Win32_Racealer_AK_MTB{
	meta:
		description = "Trojan:Win32/Racealer.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8a 8c 01 3b 2d 0b 00 8b 15 90 01 04 88 0c 02 8b 15 90 01 04 40 3b c2 72 df 90 00 } //0a 00 
		$a_00_1 = {8a 10 40 3a d3 75 f9 2b c6 3d 15 15 00 00 75 90 01 01 83 f9 18 75 1c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}