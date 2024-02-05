
rule TrojanDropper_Win32_Small_DK_MTB{
	meta:
		description = "TrojanDropper:Win32/Small.DK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {80 2f 47 80 37 15 80 37 47 f6 17 47 e2 } //01 00 
		$a_01_1 = {43 00 3a 00 5c 00 54 00 45 00 4d 00 50 00 5c 00 61 00 32 00 30 00 30 00 38 00 2e 00 65 00 78 00 65 00 } //01 00 
		$a_01_2 = {43 6f 75 6c 64 6e 27 74 20 67 65 74 20 49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //00 00 
	condition:
		any of ($a_*)
 
}