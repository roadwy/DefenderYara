
rule TrojanDropper_Win32_Moudoor_A{
	meta:
		description = "TrojanDropper:Win32/Moudoor.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {45 00 6c 00 65 00 76 00 61 00 74 00 69 00 6f 00 6e 00 3a 00 41 00 64 00 6d 00 69 00 6e 00 69 00 73 00 74 00 72 00 61 00 74 00 6f 00 72 00 21 00 6e 00 65 00 77 00 3a 00 7b 00 33 00 61 00 } //01 00 
		$a_03_1 = {eb 0f 8b 85 90 01 02 ff ff 83 c0 01 89 85 90 1b 00 ff ff 8b 8d 90 1b 00 ff ff 3b 8d 90 01 02 ff ff 73 25 8b 95 90 01 02 ff ff 03 95 90 1b 00 ff ff 0f be 02 33 85 90 1b 00 ff ff 8b 8d 90 01 02 ff ff 03 8d 90 1b 00 ff ff 88 01 eb be 6a 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}