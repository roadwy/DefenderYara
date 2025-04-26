
rule TrojanDownloader_Win32_Renos_FF{
	meta:
		description = "TrojanDownloader:Win32/Renos.FF,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {50 68 00 14 2d 00 ff ?? ?? ff 15 ?? ?? 40 00 85 c0 } //1
		$a_01_1 = {83 c1 03 eb 4b 83 c1 04 eb 46 83 c1 05 eb 41 83 c1 06 eb 3c 83 c1 07 eb 37 83 c1 08 eb 32 } //1
		$a_01_2 = {64 a1 30 00 00 00 8a 40 02 0f b6 c0 89 45 dc } //1
		$a_01_3 = {64 a1 20 00 00 00 89 45 dc eb 2f } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}