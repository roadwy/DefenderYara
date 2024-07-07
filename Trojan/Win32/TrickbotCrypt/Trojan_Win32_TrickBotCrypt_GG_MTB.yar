
rule Trojan_Win32_TrickBotCrypt_GG_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 55 f0 2b 15 90 01 04 8b 0d 90 01 04 0f af 0d 90 01 04 2b d1 2b 15 90 01 04 03 15 90 01 04 2b 15 90 01 04 2b 15 90 01 04 8b 0d 90 01 04 0f af 0d 90 01 04 0f af 0d 90 01 04 2b d1 2b 15 90 01 04 8b 4d 08 0f b6 14 11 8b 4d 0c 0f b6 04 01 33 c2 90 00 } //1
		$a_01_1 = {33 33 50 62 46 40 55 78 34 58 40 39 37 7a 37 40 63 48 61 36 48 38 3e 68 59 37 2a 3f 56 37 51 72 73 39 23 21 31 45 3f 4f 73 4b 42 4f 3e 47 38 51 5e 45 45 78 32 41 47 49 4d 44 3c 35 4e 26 78 62 64 } //1 33PbF@Ux4X@97z7@cHa6H8>hY7*?V7Qrs9#!1E?OsKBO>G8Q^EEx2AGIMD<5N&xbd
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}