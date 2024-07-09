
rule Trojan_Win32_Azorult_GH_MTB{
	meta:
		description = "Trojan:Win32/Azorult.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 5c 24 0e 8a 54 24 0f 8a c5 8a e1 34 ?? 80 f4 ?? 80 f3 ?? 80 f2 ?? 3c ?? 75 0e 80 fc ?? 75 09 80 fb ?? 75 04 84 d2 74 07 41 89 4c 24 0c eb d0 } //1
		$a_02_1 = {33 ff 8d 77 01 8d 9b 00 00 00 00 8b c7 83 e0 03 8d 4e fe 8a 5c ?? ?? 30 5c 3c ?? 30 5c 3c ?? 8b c6 83 e0 03 83 c6 06 8a 54 04 0c 30 54 3c ?? 30 54 3c ?? 8d 41 ff 83 e0 03 83 e1 03 8a 44 04 0c 30 44 3c 12 8a 44 0c 0c 30 44 3c 13 83 c7 06 81 fe e3 02 00 00 72 b4 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}