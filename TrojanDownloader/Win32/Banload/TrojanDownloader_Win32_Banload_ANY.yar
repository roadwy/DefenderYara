
rule TrojanDownloader_Win32_Banload_ANY{
	meta:
		description = "TrojanDownloader:Win32/Banload.ANY,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0c 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {83 e8 04 8b 00 8b d8 85 db 7e 2a be 01 00 00 00 8d 45 ec 8b 55 fc 0f b7 54 72 fe 66 2b d7 66 f7 d2 } //01 00 
		$a_01_1 = {5c 41 72 71 75 69 76 6f 73 20 64 65 20 70 72 6f 67 72 61 6d 61 73 5c 41 64 6f 62 65 41 52 4d 33 32 2e 65 78 65 00 } //01 00 
		$a_01_2 = {5c 00 67 00 68 00 6f 00 73 00 74 00 2e 00 7a 00 69 00 70 00 00 00 } //01 00 
		$a_01_3 = {dd 00 e6 00 c4 00 c9 00 d7 00 d2 00 dc 00 d1 00 c9 00 cd 00 c4 00 b9 00 b8 00 b1 00 ad 00 ac 00 f2 00 a6 00 b7 00 b0 00 } //01 00 
		$a_01_4 = {fb 00 04 01 e2 00 e7 00 f5 00 f0 00 fa 00 ef 00 e7 00 eb 00 e2 00 d7 00 d6 00 cf 00 cb 00 ca 00 } //00 00 
	condition:
		any of ($a_*)
 
}