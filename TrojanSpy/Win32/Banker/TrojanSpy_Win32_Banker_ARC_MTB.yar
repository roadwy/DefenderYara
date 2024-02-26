
rule TrojanSpy_Win32_Banker_ARC_MTB{
	meta:
		description = "TrojanSpy:Win32/Banker.ARC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 74 72 6c 2e 6d 74 78 2e 72 62 74 } //01 00  ctrl.mtx.rbt
		$a_01_1 = {4b 69 6c 6c 54 69 6d 65 72 } //01 00  KillTimer
		$a_80_2 = {4d 61 70 56 69 72 74 75 61 6c 4b 65 79 41 } //MapVirtualKeyA  01 00 
		$a_80_3 = {47 65 74 4b 65 79 4e 61 6d 65 54 65 78 74 41 } //GetKeyNameTextA  01 00 
		$a_03_4 = {db 6c 24 30 de c9 db 7c 24 3c 9b db 2d 90 01 04 e8 90 01 04 db 6c 24 3c de c9 dd d8 4b 75 82 83 c4 48 5b c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}