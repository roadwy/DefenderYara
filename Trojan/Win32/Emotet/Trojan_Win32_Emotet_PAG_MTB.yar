
rule Trojan_Win32_Emotet_PAG_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 00 0f b6 04 08 0f b6 0c 0a 33 d2 03 c1 b9 [0-04] f7 f1 8a da ff ?? 6a 00 6a 00 ff ?? a1 ?? ?? ?? ?? 8b f7 2b 35 ?? ?? ?? ?? 0f b6 cb 8a 04 01 8b 4d ?? 30 04 0e 47 be ?? ?? ?? ?? 8b 4d ?? 3b 7d ?? 0f 8c ?? ?? ?? ?? 8b 7d ?? 8a 45 ?? 5e 88 3f 88 47 ?? 5f 5b c9 c3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotet_PAG_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.PAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 0a 8b 01 8b 40 ?? ff d0 0f b6 c0 8b ce 50 e8 [0-04] 8b ce e8 [0-04] a1 [0-04] 8b d7 0f b6 [0-04] 47 2b 15 [0-04] 8a 04 01 b9 ?? ?? 00 00 30 04 1a 8b 45 ?? 3b 7d ?? 0f 8c } //2
		$a_01_1 = {58 00 62 00 6c 00 40 00 59 00 63 00 6d 00 41 00 5a 00 64 00 6e 00 42 00 5b 00 65 00 6f 00 43 00 5c 00 66 00 70 00 44 00 5d 00 67 00 71 00 } //1 Xbl@YcmAZdnB[eoC\fpD]gq
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}