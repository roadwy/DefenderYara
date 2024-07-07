
rule TrojanDropper_Win32_Microjoin_M{
	meta:
		description = "TrojanDropper:Win32/Microjoin.M,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c1 c2 03 32 10 40 80 38 00 75 f5 8b 04 24 83 04 24 02 8b fb 39 17 75 13 0f b7 00 c1 e0 02 03 44 90 01 02 03 c5 8b 00 03 c5 ab eb 01 af 83 3f 00 75 e3 e2 90 00 } //1
		$a_00_1 = {c6 85 00 04 00 00 00 be dd cc bb aa 68 dd cc bb aa 51 ff 53 24 89 43 60 83 ee 04 8b 0e } //2
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*2) >=2
 
}