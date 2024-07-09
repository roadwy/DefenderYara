
rule Trojan_Win32_Netwire_AB_MTB{
	meta:
		description = "Trojan:Win32/Netwire.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_02_0 = {33 c9 8a d1 80 f2 04 88 14 01 41 81 f9 ?? ?? ?? ?? 72 ef 90 0a 4f 00 be ?? ?? ?? ?? 8d bd ?? ?? ff ff f3 a5 } //1
		$a_02_1 = {33 d2 0f 1f 44 00 00 8a ca 80 f1 04 88 0c 02 42 81 fa ?? ?? ?? ?? 72 ef 90 0a 2f 00 6a ?? ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 33 d2 0f 1f 44 00 00 } //1
		$a_02_2 = {8d 45 f8 50 6a 40 68 ?? ?? ?? ?? 8d 85 ?? ?? ff ff 50 ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a ?? 6a ?? 6a ?? 68 ?? ?? ?? ?? 8d 85 ?? ?? ff ff ff d0 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? cc } //1
		$a_02_3 = {50 6a 40 68 41 06 00 00 8d 85 ?? ?? ff ff 50 ff 15 ?? ?? ?? ?? 68 00 fe 01 00 6a 07 6a 06 6a 09 68 20 41 40 00 8d 85 bc f9 ff ff ff d0 ff 15 00 00 40 00 6a 01 b9 01 00 00 00 c7 85 b8 f9 ff ff 01 00 00 00 e8 b3 df ff ff 6a 00 6a 00 ff 15 00 00 40 00 } //1
		$a_00_4 = {0f b6 84 3d f8 fe ff ff 0f b6 c9 03 c8 0f b6 c1 8b 4d fc 8a 84 05 f8 fe ff ff 30 84 0d 14 fb ff ff 50 53 83 f3 23 81 c3 81 00 00 00 2b db b8 78 00 00 00 8b d8 83 e8 30 83 c3 1f 8b db b8 4a 00 00 00 83 c0 4b 35 da 00 00 00 } //1
		$a_00_5 = {0f b6 84 15 b4 f8 ff ff 0f b6 c9 03 c8 0f b6 c1 0f b6 84 05 b4 f8 ff ff 30 84 3d bc f9 ff ff 50 53 83 e8 50 33 d8 03 d8 83 e8 52 83 f3 17 33 d8 8b db 8b d8 83 e8 27 35 b6 00 00 00 33 db 2d b9 00 00 00 83 c0 56 33 db 83 c0 7a 81 c3 fb 00 00 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=3
 
}