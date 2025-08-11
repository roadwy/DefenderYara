
rule Trojan_Win32_XWorm_AHB_MTB{
	meta:
		description = "Trojan:Win32/XWorm.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_01_0 = {0f b6 50 1b 8b 74 24 30 80 f1 e7 80 f2 78 88 4c 24 1e 0f b6 48 1c 88 54 24 1f 0f b6 50 1d 80 f1 98 80 f2 e9 88 4c 24 20 0f b6 48 1e 88 54 24 21 0f b6 50 1f } //10
		$a_03_1 = {50 57 57 ff 15 ?? ?? ?? 00 85 c0 74 0c c7 05 ?? ?? ?? 00 01 00 00 00 eb 15 ff 15 ?? ?? ?? 00 83 f8 78 75 0a c7 05 ?? ?? ?? 00 02 00 00 00 } //5
		$a_01_2 = {0b 0b 0b 83 74 74 74 f8 b9 b9 b9 ff 00 73 e1 ff 00 7f f9 ff 00 7f f9 ff 00 49 f7 ff 00 49 f7 ff 00 49 f7 ff 00 49 f7 ff 00 16 f5 ff 00 16 f5 ff 00 04 f3 ff 00 04 f3 ff 00 04 f3 ff 00 00 f2 ff 00 00 f2 ff 00 00 f2 ff 00 00 f0 ff 00 00 f0 ff } //5
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*5+(#a_01_2  & 1)*5) >=20
 
}