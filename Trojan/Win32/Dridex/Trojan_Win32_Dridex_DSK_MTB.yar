
rule Trojan_Win32_Dridex_DSK_MTB{
	meta:
		description = "Trojan:Win32/Dridex.DSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_00_0 = {8b 4c 24 34 8b 54 24 5c 8b 74 24 14 01 d6 89 74 24 2c 8b 54 24 2c 8a 1a 88 5c 24 47 35 1d ce 0a 60 09 c8 } //2
		$a_02_1 = {8a 44 05 f4 30 86 ?? ?? ?? ?? 8b c7 83 e0 03 83 c7 06 8a 44 05 f4 30 86 ?? ?? ?? ?? 83 c6 06 81 fe e2 02 00 00 72 } //2
		$a_00_2 = {8b 44 24 48 8b 4c 24 4c 66 8b 54 24 46 66 f7 d2 35 77 ae 61 00 8b 74 24 50 8b 7c 24 54 01 f6 11 ff 09 c8 66 89 54 24 46 } //2
	condition:
		((#a_00_0  & 1)*2+(#a_02_1  & 1)*2+(#a_00_2  & 1)*2) >=2
 
}