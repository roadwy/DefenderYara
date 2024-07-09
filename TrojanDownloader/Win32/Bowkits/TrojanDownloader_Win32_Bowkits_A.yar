
rule TrojanDownloader_Win32_Bowkits_A{
	meta:
		description = "TrojanDownloader:Win32/Bowkits.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {85 c0 74 2f 68 ?? ?? 40 00 a1 ?? ?? 40 00 50 e8 ?? ?? ff ff 85 c0 75 09 33 c0 a3 ?? ?? 40 00 eb 12 6a ff } //1
		$a_01_1 = {8a 00 2c 21 74 0e 04 fe 2c 02 72 08 2c 06 0f 85 } //1
		$a_01_2 = {6b 69 77 69 62 6f 74 33 00 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=3
 
}