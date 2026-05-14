
rule Trojan_Win64_Amadey_ZZ{
	meta:
		description = "Trojan:Win64/Amadey.ZZ,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 04 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_03_1 = {48 83 ec 28 41 b8 20 00 00 00 48 8d 15 ?? ?? ?? ?? 48 8d 0d ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 8d 0d ?? ?? ?? ?? 48 83 c4 28 e9 } //10
		$a_01_2 = {33 c9 49 3b c1 48 0f 45 c8 48 83 7f 18 10 48 8b c7 72 03 48 8b 07 48 83 7b 18 10 48 8b d3 72 03 48 8b 13 0f b6 04 01 41 88 04 10 49 ff c0 48 8d 41 01 4c 3b c6 7c c9 } //10
		$a_01_3 = {2b d0 48 63 c2 33 d2 49 03 c1 49 f7 f1 48 03 d1 48 8b ce 48 83 7e 18 10 72 03 48 8b 0e 0f b6 02 88 04 0f } //10
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10) >=31
 
}