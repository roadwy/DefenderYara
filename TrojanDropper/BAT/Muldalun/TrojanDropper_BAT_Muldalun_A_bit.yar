
rule TrojanDropper_BAT_Muldalun_A_bit{
	meta:
		description = "TrojanDropper:BAT/Muldalun.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {20 00 41 00 64 00 64 00 2d 00 4d 00 70 00 50 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00 20 00 2d 00 45 00 78 00 63 00 6c 00 75 00 73 00 69 00 6f 00 6e 00 50 00 61 00 74 00 68 00 20 00 43 00 3a 00 5c 00 } //1  Add-MpPreference -ExclusionPath C:\
		$a_03_1 = {45 00 6e 00 63 00 65 00 64 00 46 00 69 00 6c 00 65 00 2e 00 61 00 65 00 73 00 [0-20] 2e 00 65 00 78 00 65 00 } //1
		$a_01_2 = {44 00 72 00 6f 00 70 00 70 00 65 00 64 00 46 00 69 00 6c 00 65 00 32 00 77 00 64 00 77 00 65 00 72 00 66 00 67 00 68 00 77 00 77 00 35 00 34 00 33 00 } //1 DroppedFile2wdwerfghww543
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}