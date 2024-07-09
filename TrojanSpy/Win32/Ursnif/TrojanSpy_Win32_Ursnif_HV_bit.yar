
rule TrojanSpy_Win32_Ursnif_HV_bit{
	meta:
		description = "TrojanSpy:Win32/Ursnif.HV!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 16 85 d2 89 55 ?? 74 19 ff 45 08 8a 4d 08 33 d7 8b 7d ?? 33 d0 d3 ca 89 16 83 c6 04 ff 4d f4 75 de } //2
		$a_01_1 = {83 7d 10 00 8b 02 74 14 85 c0 75 10 83 7d 08 02 76 0a 39 42 04 75 05 39 42 08 74 16 43 8a cb d3 c0 33 c6 33 45 0c 8b f0 89 32 83 c2 04 ff 4d 08 75 ce } //2
		$a_03_2 = {03 ca 03 0d ?? ?? ?? 00 81 f9 4e 3b 55 ee 89 0d ?? ?? ?? 00 74 } //1
		$a_03_3 = {8b 10 3b 55 ?? 75 0a 8b 50 04 3b 55 ?? 75 02 8b d8 83 c0 28 49 74 04 85 db 74 e5 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=5
 
}