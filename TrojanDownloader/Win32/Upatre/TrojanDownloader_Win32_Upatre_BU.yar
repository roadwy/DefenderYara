
rule TrojanDownloader_Win32_Upatre_BU{
	meta:
		description = "TrojanDownloader:Win32/Upatre.BU,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {c7 00 63 61 74 73 05 04 00 00 00 c7 00 72 76 2e 64 05 04 00 00 00 c7 00 6c 6c 00 00 } //2
		$a_01_1 = {81 c3 02 5e d9 ff 81 c7 ad 0b 40 00 55 5a 66 81 fa 00 ff 0f 86 89 01 00 00 } //1
		$a_01_2 = {83 e9 01 34 f1 c0 c0 05 2c 05 8a da fe cb 80 e3 01 32 c3 56 } //1
		$a_01_3 = {b9 00 62 00 00 66 85 d2 f7 d2 80 c9 db 8b 4d e0 83 e9 01 89 4d e0 85 c0 76 a0 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}