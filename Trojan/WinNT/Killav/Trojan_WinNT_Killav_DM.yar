
rule Trojan_WinNT_Killav_DM{
	meta:
		description = "Trojan:WinNT/Killav.DM,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 f9 e8 00 00 00 75 90 01 01 8b 55 90 01 01 0f b7 42 05 3d 5d c2 00 00 75 90 00 } //01 00 
		$a_01_1 = {50 73 70 54 65 72 6d 69 6e 61 74 65 54 68 72 65 61 64 42 79 50 6f 69 6e 74 65 72 } //01 00  PspTerminateThreadByPointer
		$a_00_2 = {61 00 76 00 70 00 2e 00 65 00 78 00 65 00 00 00 } //01 00 
		$a_00_3 = {4e 00 56 00 43 00 41 00 67 00 65 00 6e 00 74 00 2e 00 65 00 78 00 65 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}