
rule TrojanDownloader_Win32_Chepvil_gen_C{
	meta:
		description = "TrojanDownloader:Win32/Chepvil.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3b 54 8f fc 74 0f 83 c1 ff 75 f5 83 c6 04 ff 4d fc 75 } //1
		$a_03_1 = {74 15 d1 87 cd 96 c0 65 90 09 0e 00 e8 ?? ?? ff ff 0b c0 0f 85 ?? ?? 00 00 c3 } //1
		$a_01_2 = {ae 20 5c 7e c6 1d 2f e4 64 6e 3f a2 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}