
rule TrojanDownloader_Win32_Pogolcil_E_bit{
	meta:
		description = "TrojanDownloader:Win32/Pogolcil.E!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b d8 ff 15 ?? ?? ?? 00 3d ?? ?? ?? ?? 74 ?? 8b c7 8d 0c 37 99 f7 7d ?? 8a 44 15 ?? 32 04 19 88 01 47 83 ff ?? 7c db } //1
		$a_01_1 = {0f be 39 4a 6a 08 41 5b 8b c7 33 c6 d1 ee a8 01 74 06 81 f6 20 83 b8 ed d1 ef 83 eb 01 75 e9 85 d2 75 dd 5f 5b } //1
		$a_01_2 = {74 0b 80 38 4d 75 06 80 78 01 5a 74 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}