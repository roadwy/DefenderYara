
rule Trojan_Win32_VallyRAT_GTV_MTB{
	meta:
		description = "Trojan:Win32/VallyRAT.GTV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_03_0 = {6a 04 68 00 30 00 00 51 6a 00 8d 8c 24 04 03 00 00 c7 84 24 04 03 00 00 00 00 00 00 51 6a ff 89 b4 24 14 03 00 00 ff d0 85 c0 0f 85 ?? ?? ?? ?? 56 8b b4 24 00 01 00 00 56 } //5
		$a_03_1 = {50 57 ff d6 8d 8c 24 ?? ?? ?? ?? 89 84 24 ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 57 ff d6 } //5
		$a_80_2 = {4b 54 56 63 6f 2e 64 6c 6c } //KTVco.dll  1
		$a_01_3 = {4f 6e 4c 6f 67 43 6f 6c 6c 65 63 74 6f 72 54 61 73 6b } //1 OnLogCollectorTask
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_80_2  & 1)*1+(#a_01_3  & 1)*1) >=12
 
}