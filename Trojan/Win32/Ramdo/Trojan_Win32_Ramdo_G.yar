
rule Trojan_Win32_Ramdo_G{
	meta:
		description = "Trojan:Win32/Ramdo.G,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_03_0 = {7d 28 0f b7 ?? f8 8b ?? fc 8b ?? 04 0f be ?? ?? 8b ?? fc 0f b6 ?? 33 ?? 0f b7 ?? f8 33 ?? 0f b7 ?? f8 8b 55 0c 88 ?? ?? eb bd } //1
		$a_01_1 = {81 7d f4 39 e8 ab f5 74 09 81 7d f4 27 34 f0 c5 75 } //2
		$a_01_2 = {68 0a 5a 62 59 6a 01 6a 00 e8 } //1
		$a_01_3 = {68 3e dd ef 6c 6a 03 6a 00 e8 } //1
		$a_01_4 = {68 27 a8 02 84 6a 03 6a 00 e8 } //1
		$a_03_5 = {64 a1 30 00 00 00 89 45 ?? 8b 45 ?? 8b (40|48) 0c 89 (|) 45 4d ?? 8b (|) 45 55 ?? 83 (|) c0 c2 0c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=5
 
}