
rule TrojanDropper_Win32_Livuto{
	meta:
		description = "TrojanDropper:Win32/Livuto,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 13 99 59 f7 f9 8b 45 90 01 01 80 c2 61 88 14 06 46 83 fe 0b 7c 90 00 } //01 00 
		$a_03_1 = {80 c9 ff 2a 08 47 81 ff 90 01 04 88 08 72 ea 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}