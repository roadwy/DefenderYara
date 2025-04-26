
rule Trojan_Win32_Raccoon_MBHJ_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.MBHJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 0d 30 a1 41 02 8a 94 31 4b 13 01 00 8b 0d ?? ?? ?? ?? 88 14 31 3d a8 00 00 00 75 ?? 6a 00 ff d7 a1 ?? ?? ?? ?? 46 3b f0 72 } //1
		$a_01_1 = {6c 6f 63 69 79 75 6a 61 76 65 67 69 62 65 79 00 4c 61 63 6f 6b 65 6b 75 20 72 61 74 } //1 潬楣畹慪敶楧敢y慌潣敫畫爠瑡
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}