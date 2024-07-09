
rule Trojan_Win32_Ursnif_BQ_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.BQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {0f b6 0c 28 0f b6 54 28 ?? 88 4c 24 ?? 0f b6 4c 28 ?? 8a 44 28 ?? 88 54 24 ?? 8d 54 24 ?? 52 8d 74 24 ?? 8d 7c 24 ?? 88 4c 24 ?? e8 ?? ?? ff ff } //1
		$a_02_1 = {0f b6 4c 24 ?? 8b 44 24 ?? 0f b6 54 24 ?? 88 0c 03 0f b6 4c 24 ?? 43 88 14 03 8b 54 24 ?? 43 88 0c 03 83 c5 04 83 c4 04 43 3b 2a 72 } //1
		$a_02_2 = {89 4c 24 04 83 44 24 04 06 8b 4c 24 0c 8a d0 d2 e2 80 e2 c0 08 55 00 [0-80] 8a c8 80 e1 fc c0 e1 04 08 0f 8b 4c 24 04 d2 e0 5d 24 c0 08 06 59 c3 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}