
rule TrojanSpy_Win32_Ursnif_KMG_MTB{
	meta:
		description = "TrojanSpy:Win32/Ursnif.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 04 0a 8b f8 85 c0 75 ?? 33 db 43 eb ?? 2b 74 24 ?? 03 c6 89 01 8b f7 83 c1 04 4b 75 } //1
		$a_02_1 = {03 c1 ff 45 ?? 8d 4d ?? 8b f0 e8 ?? ?? ?? ?? 8b fe 33 f6 46 eb ?? 8b 45 ?? 8b 4d ?? 8a 00 ff 45 ?? ff 45 ?? 88 01 33 f6 83 7d ?? 00 0f 84 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}