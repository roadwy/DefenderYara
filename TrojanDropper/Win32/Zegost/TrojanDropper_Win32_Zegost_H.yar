
rule TrojanDropper_Win32_Zegost_H{
	meta:
		description = "TrojanDropper:Win32/Zegost.H,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 03 00 "
		
	strings :
		$a_03_0 = {6a 02 6a 00 68 00 fc ff ff 56 ff 15 90 01 04 68 00 04 00 00 e8 90 00 } //02 00 
		$a_80_1 = {6e 65 74 73 76 63 73 5f 30 78 25 64 } //netsvcs_0x%d  01 00 
		$a_00_2 = {25 73 5c 25 64 5f 74 74 74 2e 74 6d 70 } //01 00 
		$a_00_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 76 63 68 6f 73 74 } //01 00 
		$a_00_4 = {52 73 54 72 61 79 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}