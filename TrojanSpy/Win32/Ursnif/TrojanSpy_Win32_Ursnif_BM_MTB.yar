
rule TrojanSpy_Win32_Ursnif_BM_MTB{
	meta:
		description = "TrojanSpy:Win32/Ursnif.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b d1 2b 54 24 28 83 c1 01 83 e8 01 8a 12 88 51 ff 75 90 01 01 89 4c 24 18 eb 90 00 } //1
		$a_00_1 = {c1 ea 07 83 e2 01 03 f6 8d 04 42 8b 51 0c 85 d2 89 71 08 8d 72 ff 89 71 0c 75 10 8b 11 0f b6 32 83 c2 01 89 71 08 89 11 89 79 0c 8b 51 08 8b f2 c1 ee 07 83 e6 01 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}