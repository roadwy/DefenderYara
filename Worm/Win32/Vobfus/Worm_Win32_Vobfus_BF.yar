
rule Worm_Win32_Vobfus_BF{
	meta:
		description = "Worm:Win32/Vobfus.BF,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_01_0 = {ee 14 02 00 00 00 00 00 c0 00 00 00 00 00 00 46 } //5
		$a_03_1 = {f4 02 eb 6b 74 ff eb fb cf e8 c4 71 ?? ff } //5
		$a_03_2 = {80 10 00 04 2c ff 34 6c 2c ff 08 78 ff 0d 50 00 ?? 01 6c 2c ff 6c 10 00 fc 58 2f 2c ff 00 [0-16] 6b 6e ff e7 6c 68 ff 04 2c ff 34 6c 2c ff 08 78 ff 0d 44 00 ?? 01 6c 2c ff 04 68 ff fc 58 2f 2c ff } //1
		$a_03_3 = {80 10 00 04 2c ff 34 6c 2c ff 08 78 ff 0d 50 00 ?? 01 6c 2c ff 6c 10 00 fc 58 2f 2c ff 00 26 f5 c8 5c 00 00 07 08 00 04 00 40 04 44 ff 0a 17 00 08 00 04 44 ff f5 05 2a 00 00 07 08 00 04 00 52 35 44 ff 00 10 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=11
 
}