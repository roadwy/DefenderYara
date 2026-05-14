
rule Trojan_Win32_Amadey_ZZ{
	meta:
		description = "Trojan:Win32/Amadey.ZZ,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 04 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_03_1 = {cc 6a 20 68 ?? ?? ?? ?? b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 59 c3 } //10
		$a_01_2 = {33 c9 3b 45 08 0f 45 c8 83 7a 14 10 8b c2 72 02 8b 02 83 7e 14 10 8b de 72 02 8b 1e 8a 04 01 88 04 3b 47 8d 41 01 3b 7d fc 7c d5 } //10
		$a_01_3 = {2b c8 8d 04 0a 33 d2 f7 f3 8b 5d ec 8b cb 83 7b 14 10 72 02 8b 0b 8a 04 32 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10) >=31
 
}