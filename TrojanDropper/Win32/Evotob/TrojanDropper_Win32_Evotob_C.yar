
rule TrojanDropper_Win32_Evotob_C{
	meta:
		description = "TrojanDropper:Win32/Evotob.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 24 24 53 65 63 75 72 65 20 55 41 50 } //01 00 
		$a_01_1 = {4b 42 33 30 30 30 30 36 31 } //02 00 
		$a_03_2 = {3d 00 10 00 00 74 90 01 01 3d 00 20 00 00 72 90 01 01 3d 00 30 00 00 73 90 01 01 43 eb 90 01 01 3d 00 30 00 00 72 90 01 01 6a 02 eb 90 01 01 3d 00 40 00 00 72 90 01 01 6a 03 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}