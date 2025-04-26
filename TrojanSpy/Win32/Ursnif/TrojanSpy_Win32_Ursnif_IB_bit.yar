
rule TrojanSpy_Win32_Ursnif_IB_bit{
	meta:
		description = "TrojanSpy:Win32/Ursnif.IB!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 02 85 c0 89 45 e8 74 1b 33 45 f0 ff 45 08 8a 4d 08 33 c6 d3 c8 8b 4d e8 89 4d f0 89 02 83 c2 04 4f 75 dc } //1
		$a_03_1 = {2b ca 2b ce 81 c1 ?? ?? ?? ?? 8b 41 04 2b 41 0c 03 01 3d } //1
		$a_03_2 = {8a 0e 0f b6 d0 0f b6 c9 33 d1 83 e2 0f c1 e8 04 33 04 95 ?? ?? ?? ?? c1 e9 04 8b d0 83 e2 0f 4f 33 ca c1 e8 04 46 33 04 8d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}