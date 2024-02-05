
rule Trojan_Win32_Amadey_BA_MTB{
	meta:
		description = "Trojan:Win32/Amadey.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 40 68 00 30 00 00 ff 77 50 50 ff b5 a0 fe ff ff ff 15 } //01 00 
		$a_03_1 = {8d 0c 33 03 4e 3c 6a 00 ff b1 08 01 00 00 8b 81 0c 01 00 00 03 c6 50 8b 81 04 01 00 00 03 85 98 fe ff ff 50 ff b5 a0 fe ff ff ff 15 90 02 04 8b 8d 9c fe ff ff 8d 5b 28 0f b7 47 06 41 89 8d 9c fe ff ff 3b c8 7c 90 00 } //02 00 
		$a_01_2 = {44 3a 5c 4d 6b 74 6d 70 5c 41 6d 61 64 65 79 5c 52 65 6c 65 61 73 65 5c 41 6d 61 64 65 79 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}