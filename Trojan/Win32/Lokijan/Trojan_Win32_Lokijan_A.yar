
rule Trojan_Win32_Lokijan_A{
	meta:
		description = "Trojan:Win32/Lokijan.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 4d 08 8b 55 0c 81 31 ?? ?? ?? ?? f7 11 83 c1 04 4a 75 } //1
		$a_01_1 = {8b 4d 0c 41 33 d2 f7 f1 92 3b 45 08 } //1
		$a_01_2 = {33 c0 40 c1 e0 06 8d 40 f0 64 8b 00 } //2
		$a_03_3 = {68 00 1a 40 00 e8 ?? ?? ff ff a3 ?? ?? 40 00 6a ?? 68 ?? 1a 40 00 e8 ?? ?? ff ff a3 ?? ?? 40 00 6a ?? 68 ?? 1a 40 00 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_03_3  & 1)*2) >=6
 
}