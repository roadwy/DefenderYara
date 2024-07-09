
rule TrojanDownloader_Win32_Harnig_EE{
	meta:
		description = "TrojanDownloader:Win32/Harnig.EE,SIGNATURE_TYPE_PEHSTR_EXT,6f 00 6f 00 06 00 00 "
		
	strings :
		$a_00_0 = {2f 70 72 6f 67 73 2f } //1 /progs/
		$a_02_1 = {53 33 db 56 57 89 5d ?? c6 45 ?? 68 c6 45 ?? 74 c6 45 ?? 74 c6 45 ?? 70 c6 45 ?? 3a c6 45 ?? 2f c6 45 ?? 2f } //1
		$a_02_2 = {83 f8 ff 89 45 fc 0f 84 e7 00 00 00 8d 85 d4 fe ff ff c7 85 ?? ?? ?? ?? ?? 01 00 00 50 ff 75 fc e8 ?? ?? ?? ?? 85 c0 0f 84 bd 00 00 00 53 56 8b 35 ?? ?? ?? ?? 57 bf 00 01 00 00 ff 75 08 8d 85 f8 fe ff ff 50 } //10
		$a_02_3 = {04 01 00 00 ?? ff ?? bf ?? ?? ?? ?? 83 c9 ff 33 c0 [0-05] f2 ae f7 d1 2b f9 } //10
		$a_02_4 = {8b f7 8b d1 8b ?? 83 c9 ff f2 ae 8b ca 4f c1 e9 02 f3 a5 8b ca } //50
		$a_02_5 = {55 8b ec 83 ec 44 56 ff 15 ?? ?? ?? ?? 8b f0 8a 06 3c 22 75 14 3c 22 74 08 8a 46 01 46 84 c0 75 f4 80 3e 22 75 0d 46 eb 0a 3c 20 7e 06 46 80 3e 20 7f fa 8a 06 84 c0 74 04 3c 20 7e e9 83 65 e8 00 8d 45 bc 50 } //50
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*10+(#a_02_3  & 1)*10+(#a_02_4  & 1)*50+(#a_02_5  & 1)*50) >=111
 
}