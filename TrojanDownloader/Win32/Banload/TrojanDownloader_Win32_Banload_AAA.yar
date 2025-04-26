
rule TrojanDownloader_Win32_Banload_AAA{
	meta:
		description = "TrojanDownloader:Win32/Banload.AAA,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0b 00 00 "
		
	strings :
		$a_02_0 = {4b 85 db 7c ?? 8b 45 f0 c1 e0 06 03 d8 89 5d f0 83 c7 06 83 ff 08 7c ?? 83 ef 08 8b cf 8b 5d f0 d3 eb 8b cf b8 01 00 00 00 d3 e0 50 8b 45 f0 5a 8b ca 99 f7 f9 89 55 f0 81 e3 ff 00 00 80 79 08 4b 81 cb 00 ff ff ff 43 } //10
		$a_02_1 = {8b d8 85 db 7e 2f be 01 00 00 00 8d 45 ec 8b ?? ?? ?? ?? 00 8a 54 3a ff 8b 4d fc 8a 4c 31 ff 32 d1 e8 b3 db f9 ff 8b 55 ec 8d 45 f4 e8 ?? ?? ?? ff 46 4b 75 d6 8d 45 fc 8b 55 f4 } //10
		$a_02_2 = {ff 6a 00 a1 ?? ?? ?? 00 8b 00 8b 40 30 50 e8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ff 68 ff ff 00 00 8d 55 fc b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 4d fc b2 01 a1 ?? ?? ?? ?? ?? ?? ?? ?? ff 8b d8 8d 55 f8 b8 ?? ?? ?? ?? ?? ?? ?? ?? ff 8b 55 f8 8b cb 8b 86 f8 02 00 00 e8 } //2
		$a_00_3 = {41 4c 4c 3a 21 41 44 48 3a 52 43 34 2b 52 53 41 3a } //1 ALL:!ADH:RC4+RSA:
		$a_00_4 = {4d 65 6e 73 61 67 65 6d 48 6f 74 6d 61 69 6c } //1 MensagemHotmail
		$a_00_5 = {41 6e 74 69 2d 56 69 72 75 73 20 45 4e 41 42 4c 45 6e 65 74 73 68 } //1 Anti-Virus ENABLEnetsh
		$a_00_6 = {27 1d 00 00 00 66 69 72 65 77 61 6c 6c 20 61 64 64 20 61 6c 6c 6f 77 65 64 } //1
		$a_00_7 = {6d 73 67 68 6f 74 2e 64 6c 6c } //1 msghot.dll
		$a_00_8 = {74 69 74 75 6c 6f 3d 00 ff ff ff ff 01 } //1
		$a_00_9 = {1d 00 00 00 54 65 72 72 61 20 4d 61 69 6c 20 2d 20 43 61 69 78 61 } //1
		$a_00_10 = {08 00 00 00 70 65 67 61 72 68 6f 74 } //1
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_02_2  & 1)*2+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1) >=13
 
}