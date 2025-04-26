
rule Trojan_Win32_Ursnif_AVR_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.AVR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_02_0 = {8b 55 f8 83 c2 04 89 55 f8 81 7d f8 96 16 00 00 0f 83 ?? ?? ?? ?? b8 04 00 00 00 c1 e0 02 8b 88 ?? ?? ?? ?? 89 4d ?? 83 7d ?? ?? 74 } //1
		$a_02_1 = {b8 b3 ff 00 00 2b 05 ?? ?? ?? ?? 2b c7 66 03 d0 8b 44 24 10 83 c0 04 66 89 15 ?? ?? ?? ?? 89 44 24 10 3d fc 15 00 00 0f 82 } //1
		$a_02_2 = {8b 6c 24 10 69 c1 05 34 01 00 83 c5 04 89 6c 24 10 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 81 fd fa 13 00 00 0f 82 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=1
 
}