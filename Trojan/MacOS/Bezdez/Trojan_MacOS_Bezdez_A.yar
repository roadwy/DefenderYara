
rule Trojan_MacOS_Bezdez_A{
	meta:
		description = "Trojan:MacOS/Bezdez.A,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 05 00 00 02 00 "
		
	strings :
		$a_03_0 = {ff cb 45 0f b6 27 90 02 07 89 d9 44 29 e1 31 c1 41 89 df 45 29 e7 89 8d 48 ff ff ff 0f 84 9a 00 00 00 48 8d bd 90 00 } //01 00 
		$a_00_1 = {53 74 61 72 74 69 6e 67 20 73 6e 61 6b 65 20 69 6e 20 65 76 65 6e 74 2d 64 72 69 76 65 6e 20 6d 6f 64 65 } //01 00  Starting snake in event-driven mode
		$a_00_2 = {53 74 61 72 74 69 6e 67 20 73 6e 61 6b 65 2e 2e 2e } //01 00  Starting snake...
		$a_00_3 = {73 6e 61 6b 65 5f 73 74 61 72 74 20 66 61 69 6c 65 64 3a 20 30 78 } //01 00  snake_start failed: 0x
		$a_00_4 = {2f 53 79 73 74 65 6d 2f 4c 69 62 72 61 72 79 2f 46 72 61 6d 65 77 6f 72 6b 73 2f 43 6f 72 65 46 6f 75 6e 64 61 74 69 6f 6e 2e 66 72 61 6d 65 77 6f 72 6b 2f 43 6f 72 65 46 6f 75 6e 64 61 74 69 6f 6e } //00 00  /System/Library/Frameworks/CoreFoundation.framework/CoreFoundation
	condition:
		any of ($a_*)
 
}