
rule Trojan_Win32_TrickBot_R_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.R!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {eb 09 8b 45 90 01 01 83 c0 01 89 45 90 01 01 8b 4d 90 01 01 3b 4d 10 74 4e 8b 55 08 89 55 90 01 01 8b 45 90 01 01 83 c0 01 89 45 90 01 01 8b 4d 90 01 01 8a 11 88 55 90 01 01 83 45 90 01 01 01 80 7d 90 01 01 00 75 ee 8b 45 90 01 01 2b 45 90 01 01 89 45 ec 8b 45 90 01 01 33 d2 f7 75 ec 8b 4d 08 0f be 14 11 8b 45 0c 03 45 90 01 01 0f b6 08 33 ca 8b 55 0c 03 55 90 01 01 88 0a eb a1 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_TrickBot_R_MTB_2{
	meta:
		description = "Trojan:Win32/TrickBot.R!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {b8 db 4b 68 2f f7 e1 8b c1 2b c2 d1 e8 03 c2 c1 e8 04 6b c0 1b 8b d1 2b d0 8a 04 1a 30 04 31 83 c1 01 3b cf 75 } //1
		$a_01_1 = {83 ee 08 8b da 8b ce d3 fb 83 c7 01 85 f6 88 5c 07 ff 75 ec 8b 4c 24 18 83 c5 04 83 e9 01 89 4c 24 18 0f 85 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}
rule Trojan_Win32_TrickBot_R_MTB_3{
	meta:
		description = "Trojan:Win32/TrickBot.R!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {56 47 71 4a 46 6b 59 65 4a 40 6f 4e 6b 71 37 00 } //1 䝖䩱歆教䁊乯煫7
		$a_01_1 = {48 4b 4e 44 51 5a 4b 50 67 62 53 51 53 77 50 00 } //1 䭈䑎婑偋执兓睓P
		$a_01_2 = {35 77 35 45 7a 50 43 30 43 31 30 51 72 4b 77 28 } //1 5w5EzPC0C10QrKw(
		$a_01_3 = {8b 45 f8 8d 50 01 89 d0 c1 f8 1f c1 e8 18 01 c2 0f b6 d2 29 c2 89 d0 89 45 f8 8b 45 f8 8b 94 85 ec fb ff ff 8b 45 f4 01 c2 89 d0 c1 f8 1f c1 e8 18 01 c2 0f b6 d2 29 c2 89 d0 89 45 f4 8b 45 f8 8b 84 85 ec fb ff ff 88 45 ef 8b 45 f4 8b 94 85 ec fb ff ff 8b 45 f8 89 94 85 ec fb ff ff 0f b6 55 ef 8b 45 f4 89 94 85 ec fb ff ff 8b 45 f0 8b 55 08 8d 0c 02 8b 45 f0 8b 55 08 01 d0 0f b6 00 89 c3 8b 45 f8 8b 94 85 ec fb ff ff 8b 45 f4 8b 84 85 ec fb ff ff 01 c2 89 d0 c1 f8 1f c1 e8 18 01 c2 0f b6 d2 29 c2 89 d0 8b 84 85 ec fb ff ff 31 d8 88 01 83 45 f0 01 8b 45 f0 3b 45 10 0f 82 3c ff ff ff } //1
		$a_01_4 = {8b 45 f4 8d 50 01 89 d0 c1 f8 1f c1 e8 18 01 c2 81 e2 ff 00 00 00 89 d6 29 c6 89 f0 89 45 f4 8b 45 f4 8b 94 85 e8 fb ff ff 8b 45 f0 01 c2 89 d0 c1 f8 1f c1 e8 18 01 c2 81 e2 ff 00 00 00 89 d1 29 c1 89 c8 89 45 f0 8b 45 f4 8b 84 85 e8 fb ff ff 88 45 eb 8b 45 f0 8b 94 85 e8 fb ff ff 8b 45 f4 89 94 85 e8 fb ff ff 0f b6 55 eb 8b 45 f0 89 94 85 e8 fb ff ff 8b 45 ec 8b 55 08 8d 0c 02 8b 45 ec 8b 55 08 01 d0 0f b6 00 89 c3 8b 45 f4 8b 94 85 e8 fb ff ff 8b 45 f0 8b 84 85 e8 fb ff ff 01 c2 89 d0 c1 f8 1f c1 e8 18 01 c2 81 e2 ff 00 00 00 89 d6 29 c6 89 f0 8b 84 85 e8 fb ff ff 31 d8 88 01 83 45 ec 01 8b 45 ec 3b 45 10 0f 92 c0 84 c0 0f 85 28 ff ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}