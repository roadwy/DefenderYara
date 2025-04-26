
rule TrojanSpy_Win32_Banker_USW{
	meta:
		description = "TrojanSpy:Win32/Banker.USW,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0a 00 0b 00 00 "
		
	strings :
		$a_00_0 = {40 67 6d 61 69 6c 2e 63 6f 6d } //1 @gmail.com
		$a_00_1 = {20 2d 20 4d 69 63 72 6f 73 6f 66 74 20 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 } //1  - Microsoft Internet Explore
		$a_00_2 = {20 2d 20 4d 6f 7a 69 6c 6c 61 20 46 69 72 65 66 6f 78 } //1  - Mozilla Firefox
		$a_01_3 = {55 8b ec 83 c4 e8 53 56 57 33 db 89 5d e8 89 5d ec 89 4d f8 89 55 fc 8b 45 fc e8 11 1b f8 ff 33 c0 55 68 } //1
		$a_01_4 = {53 32 48 00 64 ff 30 64 89 20 8b 45 f8 e8 4b 16 f8 ff 33 ff 33 c0 89 45 f0 8b 45 fc e8 fc 18 f8 ff 8b f0 } //1
		$a_01_5 = {85 f6 0f 8e 92 00 00 00 c7 45 f4 01 00 00 00 8d 45 ec 8b 55 fc 8b 4d f4 8a 54 0a ff e8 01 18 f8 ff 8b 45 } //1
		$a_01_6 = {ec ba 6c 32 48 00 e8 10 1c f8 ff 8b d8 4b 85 db 7c 65 8b 45 f0 c1 e0 06 03 d8 89 5d f0 83 c7 06 83 ff 08 } //1
		$a_01_7 = {7c 48 83 ef 08 8b cf 8b 5d f0 d3 eb 8b cf b8 01 00 00 00 d3 e0 50 8b 45 f0 5a 8b ca 99 f7 f9 89 55 f0 81 } //1
		$a_01_8 = {e3 ff 00 00 80 79 08 4b 81 cb 00 ff ff ff 43 8d 45 e8 8b d3 e8 a0 17 f8 ff 8b 55 e8 8b 45 f8 e8 75 18 f8 } //1
		$a_01_9 = {ff 8b 45 f8 ff 45 f4 4e 0f 85 75 ff ff ff 33 c0 5a 59 59 64 89 10 68 5a 32 48 00 8d 45 e8 ba 02 00 00 00 } //1
		$a_01_10 = {e8 aa 15 f8 ff 8d 45 fc e8 7e 15 f8 ff c3 e9 f8 0e f8 ff eb e3 5f 5e 5b 8b e5 5d } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=10
 
}