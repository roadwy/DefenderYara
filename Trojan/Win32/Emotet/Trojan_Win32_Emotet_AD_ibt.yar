
rule Trojan_Win32_Emotet_AD_ibt{
	meta:
		description = "Trojan:Win32/Emotet.AD!ibt,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_00_0 = {0f b7 01 33 d2 66 85 c0 74 30 8d 9b 00 00 00 00 66 83 f8 41 72 0e 66 83 f8 5a 77 08 0f b7 c0 83 c0 20 eb 03 0f b7 c0 69 d2 3f 00 01 00 83 c1 02 03 d0 0f b7 01 66 85 c0 75 d6 8b c2 } //1
		$a_03_1 = {33 c0 59 c3 e8 43 c8 ff ff e8 ce c9 ff ff e8 e9 d8 ff ff e8 b4 e6 ff ff e8 df ea ff ff 83 ec 08 e8 c7 b6 ff ff 83 c4 08 85 c0 74 ca c7 05 ?? ?? ?? ?? b8 26 41 00 c7 05 ?? ?? ?? ?? f0 fb 40 00 c7 05 ?? ?? ?? ?? 6a 00 00 00 c7 05 ?? ?? ?? ?? 02 00 00 00 eb 89 c7 05 ?? ?? ?? ?? 02 00 00 00 e8 97 fd ff ff 59 c3 ff 35 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 33 c0 59 } //1
		$a_03_2 = {83 f8 03 0f 87 b8 00 00 00 ff 24 85 ?? ?? ?? ?? e8 f5 b9 ff ff e8 f0 bf ff ff e8 8b 22 00 00 85 c0 75 21 c7 05 ?? ?? ?? ?? 01 00 00 00 ff 15 ?? ?? ?? ?? 33 d2 b9 a0 0f 00 00 f7 f1 8d 82 a0 0f 00 00 59 c3 } //1
		$a_00_3 = {c7 85 a0 fd ff ff 7e 6d 6f 77 c7 85 a4 fd ff ff de 73 3b 6e c7 85 a8 fd ff ff 1e 89 ec 57 c7 85 ac fd ff ff 37 b3 24 89 c7 85 b0 fd ff ff af 06 7d 16 c7 85 b4 fd ff ff e9 5d ac f9 c7 85 b8 fd ff ff d6 59 e6 e1 c7 85 bc fd ff ff 9f 03 69 fc c7 85 c0 fd ff ff d7 53 e0 58 c7 85 c4 fd ff ff 77 1b a1 28 c7 85 c8 fd ff ff 17 b5 d7 a6 c7 85 cc fd ff ff 33 d7 41 c9 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_00_3  & 1)*1) >=1
 
}