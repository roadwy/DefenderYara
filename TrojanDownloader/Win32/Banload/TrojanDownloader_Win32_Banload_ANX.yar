
rule TrojanDownloader_Win32_Banload_ANX{
	meta:
		description = "TrojanDownloader:Win32/Banload.ANX,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0b 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b f3 81 e6 ff 00 00 00 8b 55 fc 0f b6 54 32 ff 83 ea 10 88 54 30 ff 8d 45 f0 8b 55 fc 8a 54 32 ff } //01 00 
		$a_01_1 = {79 75 88 80 7c 7f 82 75 43 42 3e 75 88 75 00 } //01 00 
		$a_01_2 = {65 71 73 54 79 83 71 72 7c 75 5e 7f 84 79 76 89 00 } //0a 00 
		$a_01_3 = {8b d8 85 db 7e 2b be 01 00 00 00 8d 45 f0 8b d7 52 8b 55 fc 8a 54 32 ff 59 2a d1 f6 d2 } //01 00 
		$a_01_4 = {a3 a7 94 9c a0 9d 9a a7 9a 9a de a7 94 a7 00 } //01 00 
		$a_01_5 = {b7 ab a9 c8 a3 99 ab aa a0 a7 be 9d 98 a3 a6 93 } //00 00 
	condition:
		any of ($a_*)
 
}