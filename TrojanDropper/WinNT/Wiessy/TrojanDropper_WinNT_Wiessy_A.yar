
rule TrojanDropper_WinNT_Wiessy_A{
	meta:
		description = "TrojanDropper:WinNT/Wiessy.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {50 00 73 00 53 00 65 00 74 00 4c 00 6f 00 61 00 64 00 49 00 6d 00 61 00 67 00 65 00 4e 00 6f 00 74 00 69 00 66 00 79 00 52 00 6f 00 75 00 74 00 69 00 6e 00 65 00 } //01 00  PsSetLoadImageNotifyRoutine
		$a_00_1 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 69 00 70 00 66 00 6c 00 74 00 64 00 72 00 76 00 } //01 00  \Device\ipfltdrv
		$a_01_2 = {0f 20 c0 89 45 fc 25 ff ff fe ff 0f 22 c0 } //01 00 
		$a_01_3 = {8a 04 16 8a c8 c0 e9 04 c0 e0 04 0a c8 80 7d ff 00 75 04 c6 45 ff 01 } //00 00 
	condition:
		any of ($a_*)
 
}