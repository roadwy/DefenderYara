
rule TrojanDropper_Win32_Cutwail_W{
	meta:
		description = "TrojanDropper:Win32/Cutwail.W,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {68 00 30 00 00 50 8d 83 90 01 02 00 00 8b 80 90 01 02 ff ff 89 04 24 ff 73 34 8d 05 90 01 04 ff 90 90 90 01 04 96 90 00 } //01 00 
		$a_02_1 = {05 00 30 00 00 50 29 0c 24 ff 73 50 50 8d 83 90 01 02 00 00 8b 88 90 01 02 ff ff 89 0c 24 90 00 } //01 00 
		$a_02_2 = {30 00 00 83 90 09 07 00 c7 90 01 03 90 03 02 02 00 00 ff ff 00 90 01 04 90 03 02 02 c4 fc ec 04 8d 90 01 05 ff 90 01 05 8d 90 01 05 ff 90 01 05 8d 90 01 05 ff 90 01 05 33 f6 90 03 02 03 0b f0 4e 23 f0 8d 90 00 } //01 00 
		$a_02_3 = {0f 85 19 ff ff ff 33 c0 c9 c3 8d 90 01 05 64 8b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}