
rule TrojanSpy_Win32_Ursnif_KD_bit{
	meta:
		description = "TrojanSpy:Win32/Ursnif.KD!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {33 c6 33 44 24 14 8a cb c0 e1 03 d3 c8 83 f3 01 8b f7 89 02 83 c2 04 ff 4c 24 10 } //1
		$a_03_1 = {8b 06 8b cb 83 e1 01 c1 e1 03 d3 e0 01 05 ?? ?? ?? ?? 4b 75 09 } //1
		$a_03_2 = {74 34 8b 4e 3c 8b 54 31 08 81 f2 ?? ?? ?? ?? 74 20 8b 48 0c 8b 74 24 08 8b 40 10 89 0e 8b 74 24 0c 89 06 03 c1 8b 4c 24 10 33 c2 89 01 33 c0 } //1
		$a_03_3 = {8a cb d3 c8 8b d7 50 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 43 81 c7 00 10 00 00 3b de 72 e1 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}