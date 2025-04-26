
rule TrojanSpy_Win32_Ursnif_RA_MTB{
	meta:
		description = "TrojanSpy:Win32/Ursnif.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {81 c7 30 a5 06 01 89 7d 00 83 c5 04 } //1
		$a_03_1 = {03 f0 8b ce 6b c9 [0-0a] 03 d1 0f b7 0d [0-07] 8b 7d 00 } //1
		$a_01_2 = {8a 84 06 e1 bf 01 00 8b 0d 90 d7 43 04 88 04 0e } //1
		$a_03_3 = {81 f9 00 01 00 00 0f 90 0a 4f 00 8a 86 ?? ?? ?? ?? 88 81 90 1b 01 75 [0-2f] 8b 0d ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 41 88 9e 90 1b 01 89 0d 90 1b 04 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=2
 
}