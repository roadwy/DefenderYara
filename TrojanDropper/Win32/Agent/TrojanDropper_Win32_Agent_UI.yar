
rule TrojanDropper_Win32_Agent_UI{
	meta:
		description = "TrojanDropper:Win32/Agent.UI,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {41 63 63 65 70 74 3a 20 2a 2f 2a 0d 0a 0d 0a 00 41 67 65 6e 74 25 6c 64 00 } //01 00 
		$a_00_1 = {72 65 6c 64 65 6c 00 00 74 72 75 73 73 00 } //01 00 
		$a_02_2 = {68 2f 2f 00 00 50 e8 90 01 04 83 c4 18 3b c7 74 90 01 01 40 eb 90 01 01 8d 85 90 01 01 fc ff ff 50 8d 85 90 01 01 fb ff ff 50 e8 90 01 04 59 8d 85 90 01 01 fb ff ff 59 50 8d 85 90 01 01 fe ff ff 50 e8 90 01 04 39 7e 10 59 59 74 90 01 01 c7 45 08 80 00 00 00 eb 90 01 01 8b 46 28 89 45 08 8d 85 90 01 01 fe ff ff 50 53 90 00 } //01 00 
		$a_02_3 = {68 00 00 01 80 50 ff 15 90 01 04 89 45 fc ff 76 24 8d 85 90 01 01 fe ff ff 57 57 50 57 57 ff 15 90 01 04 ff 15 90 01 04 57 57 57 ff 15 90 01 04 50 ff 15 90 01 04 57 57 8d 45 e0 57 50 ff 15 90 01 04 ff d3 2b 45 08 3d e8 03 00 00 73 90 01 01 6a 32 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}