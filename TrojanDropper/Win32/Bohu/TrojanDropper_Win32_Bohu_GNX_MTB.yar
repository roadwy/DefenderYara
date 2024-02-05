
rule TrojanDropper_Win32_Bohu_GNX_MTB{
	meta:
		description = "TrojanDropper:Win32/Bohu.GNX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {41 00 f0 a1 41 00 9b a2 41 00 9b a2 41 00 1a a2 41 00 2a a2 41 00 9b a2 41 00 a4 a2 41 00 a4 a2 41 00 8e a1 41 00 8e a1 41 00 9c a1 41 00 9b a2 41 00 a6 a1 41 00 a6 a1 41 00 9b a2 41 00 9b a2 41 00 9b a2 } //00 00 
	condition:
		any of ($a_*)
 
}