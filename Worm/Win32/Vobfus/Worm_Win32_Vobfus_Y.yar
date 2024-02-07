
rule Worm_Win32_Vobfus_Y{
	meta:
		description = "Worm:Win32/Vobfus.Y,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {f4 02 eb 6b 74 ff eb fb cf e8 c4 f5 00 00 00 00 } //01 00 
		$a_03_1 = {80 10 00 04 90 01 01 ff 34 6c 90 01 01 ff 08 90 01 02 0d 90 01 01 00 90 01 02 6c 90 01 01 ff 6c 10 00 fc 58 2f 90 01 01 ff 00 23 6b 6e ff e7 6c 68 ff 04 90 01 01 ff 34 6c 90 01 01 ff 08 90 01 02 0d 90 01 01 00 90 01 02 6c 90 01 01 ff 04 68 ff fc 58 2f 90 01 01 ff 00 1f 6c 64 ff 04 90 01 01 ff 34 6c 90 01 01 ff 08 90 01 02 0d 90 01 01 00 90 01 02 6c 90 01 01 ff 04 64 ff fc 58 90 00 } //01 00 
		$a_01_2 = {ee 14 02 00 00 00 00 00 c0 00 00 00 00 00 00 46 } //01 00 
		$a_00_3 = {76 62 2e 64 72 69 76 65 6c 69 73 74 62 6f 78 } //00 00  vb.drivelistbox
	condition:
		any of ($a_*)
 
}