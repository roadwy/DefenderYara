
rule TrojanSpy_Win32_Ursnif_AV_MTB{
	meta:
		description = "TrojanSpy:Win32/Ursnif.AV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {81 c2 c4 8a 61 01 89 15 90 01 04 a1 90 01 04 03 45 ec 8b 0d 90 01 04 89 88 dd e3 ff ff 8b 15 90 01 04 03 15 90 01 04 81 fa b5 02 00 00 75 2b 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule TrojanSpy_Win32_Ursnif_AV_MTB_2{
	meta:
		description = "TrojanSpy:Win32/Ursnif.AV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_02_0 = {81 c2 98 42 4c 01 89 15 90 01 04 a1 90 01 04 03 45 e4 8b 0d 90 01 04 89 88 36 ed ff ff 0f b7 55 e8 90 00 } //1
		$a_00_1 = {81 c5 24 12 11 01 83 c0 a0 03 f8 8b 44 24 10 89 ac 01 6d f5 ff ff 8d 0c 3f 2b ca 8b 54 24 10 } //1
		$a_02_2 = {81 c1 e8 8b f2 01 89 0d 90 01 04 02 c3 89 0e 04 02 66 0f b6 c8 66 6b c9 06 66 03 0d 90 00 } //1
		$a_02_3 = {81 c2 80 e7 bf 01 89 15 90 01 04 a1 90 01 04 03 45 e4 8b 0d 90 01 04 89 88 ee e1 ff ff 0f b7 55 e8 6b d2 06 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=1
 
}
rule TrojanSpy_Win32_Ursnif_AV_MTB_3{
	meta:
		description = "TrojanSpy:Win32/Ursnif.AV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_02_0 = {81 c1 1c 9b 0d 02 89 0d 90 01 04 8b 15 90 01 04 03 55 e8 a1 90 01 04 89 82 f1 f5 ff ff 0f b7 4d ec 0f af 0d 90 01 04 2b 0d 90 01 04 66 89 4d ec 0f b7 55 ec a1 90 01 04 8d 4c 02 f7 89 0d 90 01 04 e9 90 00 } //1
		$a_02_1 = {05 bc 37 5e 02 a3 90 01 04 8b 0d 90 01 04 03 4d f0 8b 15 90 01 04 89 91 04 ed ff ff 0f b7 45 f4 8b 0d 90 01 04 8d 54 01 5f 89 15 90 01 04 81 3d 90 01 04 b8 17 00 00 75 90 00 } //1
		$a_02_2 = {05 84 5d c2 01 89 03 66 8b 1d 90 01 04 a3 90 01 04 8b c6 69 c0 5b 5a 00 00 03 c8 0f b7 05 90 01 04 3d ef 9d 0a 00 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=1
 
}