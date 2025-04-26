
rule Trojan_Win32_ClipBanker_MD_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4d fc 8b 55 f8 8b 04 8a 50 8d 8d f0 fe ff ff 51 ff 15 ?? ?? ?? ?? 68 00 01 00 00 e8 ?? ?? ?? ?? 83 c4 04 89 85 ec fe ff ff 8b 55 fc 8b 45 f4 8b 8d ec fe ff ff 89 0c ?? 68 80 00 00 00 8b 55 fc 8b 45 f4 8b 0c ?? 51 6a ff 8d 95 f0 fe ff ff 52 6a 00 6a 00 ff 15 ?? ?? ?? ?? e9 } //1
		$a_00_1 = {89 65 f0 c7 85 cc fd ff ff 00 00 00 00 c7 85 bc fd ff ff 00 00 00 00 c7 85 c4 fd ff ff 00 00 00 00 c7 85 c0 fd ff ff 00 00 00 00 c7 85 b8 fd ff ff 00 00 00 00 c7 85 e0 fd ff ff 00 00 00 00 c7 85 b4 7d ff ff 00 00 00 00 c7 45 ec 00 00 00 00 c7 85 c8 fd ff ff 00 00 00 00 66 c7 85 b8 7d ff ff 00 00 b9 ff 1f 00 00 33 c0 8d bd ba 7d ff ff f3 ab 66 ab 66 c7 85 e4 fd ff ff 00 00 b9 81 00 00 00 33 c0 8d bd e6 fd ff ff f3 ab 66 ab 66 c7 85 d0 fd ff ff 00 00 33 c0 89 85 d2 fd ff ff 89 85 d6 fd ff ff 89 85 da fd ff ff 66 89 85 de fd ff ff c7 45 fc 00 00 00 00 6a 02 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}