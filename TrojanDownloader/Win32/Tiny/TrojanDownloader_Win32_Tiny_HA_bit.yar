
rule TrojanDownloader_Win32_Tiny_HA_bit{
	meta:
		description = "TrojanDownloader:Win32/Tiny.HA!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b 44 24 08 8b 54 24 04 56 8b f1 85 c0 74 30 53 57 8d 38 8b 46 04 33 db 8a 1a 8b c8 81 e1 ff 00 00 00 33 cb c1 e8 08 8b 0c 8d 90 01 02 40 00 33 c8 42 4f 89 4e 04 75 dc 90 00 } //01 00 
		$a_01_1 = {4b 48 2a 5e 32 33 34 73 65 26 25 32 } //00 00 
	condition:
		any of ($a_*)
 
}