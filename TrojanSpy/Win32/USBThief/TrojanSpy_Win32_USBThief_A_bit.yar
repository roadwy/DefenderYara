
rule TrojanSpy_Win32_USBThief_A_bit{
	meta:
		description = "TrojanSpy:Win32/USBThief.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b f0 85 f6 74 2a 8b 4d 08 53 51 ff 15 90 01 04 03 c6 83 e7 0f 76 14 8d 9b 00 00 00 00 3b f0 73 0e 4f 0f b7 16 8d 74 56 02 75 f2 3b f0 72 08 90 00 } //01 00 
		$a_01_1 = {5c 55 70 61 6e 5a 68 6f 6e 67 4d 61 5c 52 65 6c 65 61 73 65 5c 55 70 61 6e 5a 68 6f 6e 67 4d 61 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}