
rule Trojan_Win32_Emotet_PJ_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 04 00 00 "
		
	strings :
		$a_02_0 = {c7 04 24 38 d5 39 53 e8 ?? ?? ?? ?? 89 [0-02] c7 04 24 f6 61 79 e6 e8 ?? ?? ?? ?? 89 [0-02] c7 04 24 2d 00 b4 ad e8 ?? ?? ?? ?? 89 [0-02] c7 04 24 7e 18 2a bf e8 ?? ?? ?? ?? 89 [0-02] c7 04 24 10 59 4b 4d e8 ?? ?? ?? ?? 89 [0-02] c7 04 24 e0 95 66 b3 e8 ?? ?? ?? ?? 89 [0-02] c7 04 24 7b 8c 58 56 e8 } //20
		$a_02_1 = {c7 04 24 17 cf 43 f9 e8 ?? ?? ?? ?? 89 [0-05] c7 04 24 31 82 6d 75 e8 ?? ?? ?? ?? 89 [0-05] c7 04 24 16 72 b3 9b e8 ?? ?? ?? ?? 89 [0-05] c7 04 24 b9 fb 3e 2c e8 ?? ?? ?? ?? 89 [0-05] c7 04 24 3d 1f 33 0a e8 ?? ?? ?? ?? 89 [0-05] c7 04 24 e6 9c f6 80 e8 ?? ?? ?? ?? 89 [0-05] c7 04 24 f8 de d1 9c e8 } //20
		$a_02_2 = {c7 44 24 0c 01 00 00 00 c7 44 24 08 10 00 00 00 8b 45 10 89 44 24 04 8b 45 ?? 89 04 24 ff d7 83 ec 10 85 c0 0f 84 ?? ?? ?? ?? 8d 45 ?? 89 44 24 10 c7 44 24 0c 01 00 00 00 8b 45 ?? 89 44 24 08 c7 44 24 04 01 68 00 00 8b 45 ?? 89 04 24 ff 55 } //1
		$a_02_3 = {c7 44 24 0c 01 00 00 00 c7 44 24 08 10 00 00 00 89 5c 24 04 8b 44 24 ?? 89 04 24 ff 54 24 ?? 83 ec 10 85 c0 0f 84 ?? ?? ?? ?? 8d 44 24 ?? 89 44 24 10 c7 44 24 0c 01 00 00 00 8b 44 24 ?? 89 44 24 08 c7 44 24 04 01 68 00 00 8b 44 24 ?? 89 04 24 ff } //1
	condition:
		((#a_02_0  & 1)*20+(#a_02_1  & 1)*20+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=21
 
}