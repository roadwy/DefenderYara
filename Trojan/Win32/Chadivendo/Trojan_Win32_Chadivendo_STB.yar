
rule Trojan_Win32_Chadivendo_STB{
	meta:
		description = "Trojan:Win32/Chadivendo.STB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {8a 0c 3a 8a c1 c0 e1 02 c0 f8 06 0a c1 88 04 3a 42 3b d6 7c eb } //1
		$a_03_1 = {8b c3 99 f7 fe 8a 04 3a 30 [0-05] 43 81 fb ?? ?? ?? ?? 7c } //1
		$a_03_2 = {8d 45 f0 c7 45 f0 ?? ?? ?? ?? 50 8b 45 fc c7 45 f4 ?? ?? ?? ?? ff d0 } //1
		$a_00_3 = {80 4f 00 00 00 5f ff ff ff ff 47 6c 6f 62 61 6c 5c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}