
rule Trojan_Win32_Ursnif_AN_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {0f b7 c6 89 44 24 20 0f b7 c1 8b cd 99 2b c8 8b 44 24 20 1b fa 83 c1 67 99 83 d7 00 } //1
		$a_00_1 = {1b fa 0f a4 c8 03 c1 e1 03 } //1
		$a_02_2 = {8d 85 46 40 00 00 81 c2 ?? ?? ?? ?? 66 03 f0 89 54 24 20 8b 44 24 1c 66 89 35 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 89 10 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}