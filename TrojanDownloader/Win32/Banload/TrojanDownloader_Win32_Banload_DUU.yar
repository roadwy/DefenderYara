
rule TrojanDownloader_Win32_Banload_DUU{
	meta:
		description = "TrojanDownloader:Win32/Banload.DUU,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 0b 00 00 "
		
	strings :
		$a_00_0 = {5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 5c 00 } //1 \system\
		$a_01_1 = {4a 00 53 00 48 00 4e 00 46 00 49 00 55 00 59 00 } //1 JSHNFIUY
		$a_01_2 = {45 00 39 00 49 00 4e 00 47 00 39 00 38 00 59 00 } //1 E9ING98Y
		$a_01_3 = {33 00 30 00 46 00 4b 00 39 00 38 00 38 00 34 00 } //1 30FK9884
		$a_01_4 = {48 00 30 00 39 00 37 00 53 00 48 00 30 00 30 00 } //1 H097SH00
		$a_01_5 = {39 00 56 00 48 00 42 00 57 00 30 00 38 00 48 00 } //1 9VHBW08H
		$a_01_6 = {49 00 50 00 35 00 38 00 34 00 35 00 34 00 4a 00 } //1 IP58454J
		$a_01_7 = {4f 00 4c 00 50 00 4a 00 44 00 48 00 55 00 59 00 } //1 OLPJDHUY
		$a_01_8 = {4a 00 53 00 49 00 4b 00 4a 00 49 00 4b 00 39 00 35 00 32 00 34 00 } //1 JSIKJIK9524
		$a_02_9 = {c7 45 fc 0c 00 00 00 8b 45 d8 50 8b 4d dc 51 ff 15 c4 10 40 00 c7 45 fc 0d 00 00 00 8d 55 d8 89 95 74 ff ff ff c7 85 6c ff ff ff 08 40 00 00 6a 02 8d 85 6c ff ff ff 50 ff 15 80 10 40 00 dd 9d 30 ff ff ff c7 45 fc 0e 00 00 00 c7 45 84 04 00 02 80 c7 85 7c ff ff ff 0a 00 00 00 c7 45 94 04 00 02 80 c7 45 8c 0a 00 00 00 c7 85 64 ff ff ff ?? ?? 40 00 c7 85 5c ff ff ff 08 00 00 00 8d 95 5c ff ff ff 8d 4d 9c ff 15 d8 10 40 00 c7 85 74 ff ff ff ?? ?? 40 00 c7 85 6c ff ff ff 08 00 00 00 8d 95 6c ff ff ff 8d 4d ac ff 15 d8 10 40 00 8d 8d 7c ff ff ff 51 8d 55 8c 52 8d 45 9c 50 6a 10 8d 4d ac 51 ff 15 4c 10 40 00 8d 95 7c ff ff ff } //5
		$a_00_10 = {c7 85 68 ff ff ff 08 00 00 00 6a 00 8d 85 68 ff ff ff 50 ff 15 a0 10 40 00 8b d0 8d 4d d4 ff 15 e8 10 40 00 50 ff 15 30 10 40 00 8b d0 8d 4d d0 ff 15 e8 10 40 00 50 ff 15 3c 10 40 00 33 c9 85 c0 0f 9f c1 f7 d9 66 89 8d 4c ff ff ff 8d 55 d0 52 8d 45 d4 50 6a 02 ff 15 c0 10 40 00 83 c4 0c 8d 8d 68 ff ff ff ff 15 08 10 40 00 0f bf 8d 4c ff ff ff 85 c9 74 46 c7 45 fc 0c 00 00 00 8b 55 d8 52 8b 45 dc 50 ff 15 34 10 40 00 89 85 70 ff ff ff c7 85 68 ff ff ff 08 00 00 00 6a 02 8d 8d 68 ff ff ff 51 ff 15 80 10 40 00 dd 9d 50 ff ff ff 8d 8d 68 ff ff ff ff 15 08 10 40 00 9b } //5
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_02_9  & 1)*5+(#a_00_10  & 1)*5) >=19
 
}