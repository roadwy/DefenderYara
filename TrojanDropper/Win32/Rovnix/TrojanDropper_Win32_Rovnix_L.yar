
rule TrojanDropper_Win32_Rovnix_L{
	meta:
		description = "TrojanDropper:Win32/Rovnix.L,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {81 3a 33 33 33 33 75 02 eb 02 } //01 00 
		$a_03_1 = {81 f9 55 aa 00 00 74 09 c7 45 90 01 01 cb 00 00 c0 90 00 } //01 00 
		$a_01_2 = {0f b7 88 fe 01 00 00 81 f9 55 aa 00 00 74 0c } //00 00 
	condition:
		any of ($a_*)
 
}