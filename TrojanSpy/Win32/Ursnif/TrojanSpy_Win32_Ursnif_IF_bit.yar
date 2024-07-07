
rule TrojanSpy_Win32_Ursnif_IF_bit{
	meta:
		description = "TrojanSpy:Win32/Ursnif.IF!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 07 8a 4c 24 90 01 01 d3 c0 83 c7 04 33 c6 33 c3 8b f0 89 32 83 c2 04 ff 4c 24 90 01 01 75 e0 90 00 } //1
		$a_01_1 = {8a 04 0f 32 c3 88 01 41 4e 75 f5 } //1
		$a_03_2 = {50 8b 45 08 ff 30 81 f3 20 62 6c 73 ff 75 90 01 01 03 df 03 5d 90 01 01 89 5d 90 01 01 e8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}