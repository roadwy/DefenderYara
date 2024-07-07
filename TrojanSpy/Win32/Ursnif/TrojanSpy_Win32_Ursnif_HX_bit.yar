
rule TrojanSpy_Win32_Ursnif_HX_bit{
	meta:
		description = "TrojanSpy:Win32/Ursnif.HX!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 02 85 c0 8b f0 74 90 01 01 33 c1 33 44 24 10 43 8a cb d3 c8 8b ce 89 02 83 c2 04 ff 4c 24 0c 75 90 00 } //1
		$a_01_1 = {8a cb d3 c0 33 c6 33 44 24 10 8b f0 89 32 83 c2 04 ff 4c 24 0c 75 } //1
		$a_03_2 = {8b 10 3b 55 90 01 01 75 0a 8b 50 04 3b 55 90 01 01 75 02 8b d8 83 c0 28 49 74 04 85 db 74 e5 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule TrojanSpy_Win32_Ursnif_HX_bit_2{
	meta:
		description = "TrojanSpy:Win32/Ursnif.HX!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {8d 04 11 33 45 d8 83 e6 1f 33 45 dc } //1
		$a_01_1 = {43 8a cb d3 c0 33 c6 33 44 24 10 8b f0 89 32 } //1
		$a_03_2 = {8b 08 69 c9 90 01 04 81 c1 90 01 04 89 0a 69 c9 90 01 04 81 c1 90 01 04 56 66 8b f1 69 c9 90 01 04 66 89 72 04 be 90 01 04 03 ce 57 89 08 66 89 4a 06 33 ff 90 00 } //1
		$a_03_3 = {8b 08 69 c9 90 01 04 03 ce 88 4c 3a 08 47 89 08 83 ff 08 72 ea 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}