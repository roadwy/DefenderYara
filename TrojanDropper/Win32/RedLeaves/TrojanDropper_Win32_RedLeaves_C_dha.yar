
rule TrojanDropper_Win32_RedLeaves_C_dha{
	meta:
		description = "TrojanDropper:Win32/RedLeaves.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_81_0 = {44 61 74 61 20 45 52 52 4f 52 21 21 21 20 20 20 20 20 50 6c 65 61 73 65 20 63 68 65 63 6b 20 79 6f 75 72 20 69 6e 70 75 74 21 } //1 Data ERROR!!!     Please check your input!
		$a_01_1 = {45 58 49 54 3f 00 00 00 cd cb b3 f6 00 00 00 00 00 } //1
		$a_03_2 = {55 8b ec 8b 55 0c 33 c0 85 d2 7e 0d 8b 4d 08 90 90 80 34 08 ?? 40 3b c2 7c f7 33 c0 5d c2 08 00 } //1
		$a_01_3 = {33 db 39 58 f4 0f 95 c3 89 18 33 db 39 58 08 0f 95 c3 89 58 14 33 db 39 58 1c 0f 95 c3 83 c0 3c 2b d1 89 58 ec 75 d9 89 95 d8 f5 ff ff 8d 9d 68 f8 ff ff } //1
		$a_01_4 = {43 89 9d cc f5 ff ff 89 18 83 c9 ff 83 38 09 7f 1a 8b 95 d8 f5 ff ff 41 83 f9 51 7c 99 8b 85 d0 f5 ff ff 8b 9d d4 f5 ff ff eb 1b 8b 9d d4 f5 ff ff c7 00 00 00 00 00 8b 85 d0 f5 ff ff 8b 10 4a 83 eb 02 83 e8 08 83 fb ff 7c 18 b9 01 00 00 00 } //1
	condition:
		((#a_81_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}