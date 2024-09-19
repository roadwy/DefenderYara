
rule Trojan_Win64_Latrodectus_DD_MTB{
	meta:
		description = "Trojan:Win64/Latrodectus.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_03_0 = {41 0f b7 03 48 8b d5 49 8d 0c 86 42 8b 34 09 41 8b 0a 49 03 c9 e8 ?? ?? ?? ?? 85 c0 74 ?? ff c3 49 83 c3 02 49 83 c2 04 3b df 7c } //1
		$a_03_1 = {49 63 ca 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? 44 03 d6 48 f7 e1 [0-32] 48 c1 ?? 04 48 6b ?? ?? 48 2b c8 49 ?? cb 8a 44 0c 20 42 32 04 0b 41 88 01 4c 03 ce 45 3b d4 72 } //1
		$a_03_2 = {48 63 cb 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? 41 03 df 48 f7 e1 48 c1 ea 03 48 6b c2 1a 48 2b c8 48 2b ce 8a 44 0c 20 43 32 04 1a 41 88 03 4d 03 df 81 fb 00 ec 01 00 72 } //1
		$a_03_3 = {4d 63 c1 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? 49 f7 e0 48 c1 ea 02 48 6b c2 16 4c 2b c0 41 8b c1 44 03 ce 99 4d 2b c3 f7 fb 48 ba ?? ?? ?? ?? ?? ?? ?? ?? 48 63 c8 42 8a 44 04 20 32 04 11 41 88 02 4c 03 d6 45 3b cc 72 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=1
 
}