
rule Trojan_Win32_Zloader_SIBB_MTB{
	meta:
		description = "Trojan:Win32/Zloader.SIBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {21 f0 89 45 90 01 01 68 90 01 04 e8 90 01 04 83 c4 04 89 fe f7 d6 68 90 01 04 e8 90 01 04 83 c4 04 83 e7 90 01 01 21 f0 57 50 e8 90 01 04 83 c4 08 33 45 90 1b 00 35 90 01 04 89 45 90 1b 00 e9 90 00 } //1
		$a_03_1 = {88 c7 f6 d7 0f b6 c7 50 56 e8 90 01 04 83 c4 08 88 45 90 01 01 8b 45 90 01 01 88 c3 f6 d3 68 90 01 04 e8 90 01 04 83 c4 04 0f b6 4d 90 01 01 22 7d 90 1b 02 20 d8 0f b6 c0 08 4d 90 1b 01 0f b6 cf 51 50 e8 90 01 04 83 c4 08 89 c3 ff 75 90 1b 02 56 e8 90 01 04 83 c4 08 32 5d 90 1b 01 8b 45 0c 88 1c 38 8d 7f 01 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}