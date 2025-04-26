
rule Trojan_Win32_Waltrodock_A{
	meta:
		description = "Trojan:Win32/Waltrodock.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {52 6b 74 44 6f 77 6e 6c 6f 61 64 25 64 00 } //1 歒䑴睯汮慯╤d
		$a_01_1 = {73 6f 66 74 75 72 6c 25 64 00 } //1 潳瑦牵╬d
		$a_03_2 = {75 02 33 c0 41 81 f9 04 01 00 00 7c d9 90 09 1a 00 8a 90 90 ?? ?? ?? ?? 8a 9c 0c ?? ?? ?? ?? 32 da 40 83 f8 10 88 9c 0c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}