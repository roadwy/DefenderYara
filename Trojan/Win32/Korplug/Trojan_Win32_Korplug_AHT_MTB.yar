
rule Trojan_Win32_Korplug_AHT_MTB{
	meta:
		description = "Trojan:Win32/Korplug.AHT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {c6 45 e4 47 c6 45 e5 65 c6 45 e6 74 c6 45 e7 4d c6 45 e8 6f c6 45 e9 64 c6 45 ea 75 c6 45 eb 6c c6 45 ec 65 c6 45 ed 46 c6 45 ee 69 c6 45 ef 6c c6 45 f0 65 c6 45 f1 4e c6 45 f2 61 c6 45 f3 6d c6 45 f4 65 c6 45 f5 41 c6 45 f6 00 } //2
		$a_03_1 = {83 f2 4c 88 95 5f fe ?? ?? 0f be 85 5f fe ?? ?? 83 f0 76 88 85 5f fe ?? ?? 8b 8d a4 fe ?? ?? 03 8d 54 fe ?? ?? 0f b6 09 8b 85 54 fe ?? ?? 33 d2 f7 75 b4 8b 45 d8 0f be 14 10 33 ca } //3
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*3) >=5
 
}