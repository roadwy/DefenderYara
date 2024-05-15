
rule Trojan_Win32_Ymacco_YAA_MTB{
	meta:
		description = "Trojan:Win32/Ymacco.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 04 24 c6 00 ea 2d e3 39 46 00 05 6a 3a 46 00 } //0a 00 
		$a_03_1 = {80 30 73 8b 04 24 89 c6 66 ad 89 f2 58 ff 70 fb 8f 02 b9 90 01 04 81 e9 90 01 04 8d 34 08 b9 90 00 } //00 00 
		$a_00_2 = {5d 04 00 00 14 71 06 80 5c 2b } //00 00 
	condition:
		any of ($a_*)
 
}