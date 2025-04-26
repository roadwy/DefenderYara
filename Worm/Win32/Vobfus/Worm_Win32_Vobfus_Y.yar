
rule Worm_Win32_Vobfus_Y{
	meta:
		description = "Worm:Win32/Vobfus.Y,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {f4 02 eb 6b 74 ff eb fb cf e8 c4 f5 00 00 00 00 } //1
		$a_03_1 = {80 10 00 04 ?? ff 34 6c ?? ff 08 ?? ?? 0d ?? 00 ?? ?? 6c ?? ff 6c 10 00 fc 58 2f ?? ff 00 23 6b 6e ff e7 6c 68 ff 04 ?? ff 34 6c ?? ff 08 ?? ?? 0d ?? 00 ?? ?? 6c ?? ff 04 68 ff fc 58 2f ?? ff 00 1f 6c 64 ff 04 ?? ff 34 6c ?? ff 08 ?? ?? 0d ?? 00 ?? ?? 6c ?? ff 04 64 ff fc 58 } //1
		$a_01_2 = {ee 14 02 00 00 00 00 00 c0 00 00 00 00 00 00 46 } //1
		$a_00_3 = {76 62 2e 64 72 69 76 65 6c 69 73 74 62 6f 78 } //1 vb.drivelistbox
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}