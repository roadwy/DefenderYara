
rule Trojan_Win32_Ursnif_AH_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6b d2 07 03 15 ?? ?? ?? ?? 89 55 e0 8b 45 e8 83 e8 4e 2b 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 2b c8 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 2b 55 e0 83 c2 78 3b 55 f0 } //1
		$a_81_1 = {50 65 72 68 61 70 73 44 61 6e 63 65 2e 70 64 62 } //1 PerhapsDance.pdb
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Ursnif_AH_MTB_2{
	meta:
		description = "Trojan:Win32/Ursnif.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {00 8b 39 81 fb ?? ?? ?? ?? 75 ?? 8d 8a ?? ?? ff ff 66 03 c1 8b 4c 24 10 66 a3 ?? ?? ?? 00 83 44 24 10 04 81 c7 78 e0 3a 01 89 39 8d 4b 49 8d 0c 51 03 f1 8b 0d ?? ?? ?? 00 8d 0c b1 03 ce 83 6c 24 14 01 0f b7 d1 0f 85 ?? ff ff ff } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}