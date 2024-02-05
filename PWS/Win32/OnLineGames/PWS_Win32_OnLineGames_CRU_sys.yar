
rule PWS_Win32_OnLineGames_CRU_sys{
	meta:
		description = "PWS:Win32/OnLineGames.CRU!sys,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {55 8b ec 81 ec b0 01 00 00 80 65 f0 00 80 65 e0 00 80 65 ff 00 53 56 be 90 01 04 57 c6 45 e4 69 c6 45 e5 65 c6 45 e6 78 c6 45 e7 70 c6 45 e8 6c c6 45 e9 6f c6 45 ea 72 c6 45 eb 65 c6 45 ec 2e c6 45 ed 65 c6 45 ee 78 c6 45 ef 65 c6 45 d4 65 c6 45 d5 78 c6 45 d6 70 c6 45 d7 6c c6 45 d8 6f c6 45 d9 72 c6 45 da 65 c6 45 db 72 c6 45 dc 2e c6 45 dd 65 c6 45 de 78 c6 45 df 65 c6 45 f4 73 c6 45 f5 76 c6 45 f6 63 c6 45 f7 68 c6 45 f8 6f c6 45 f9 73 c6 45 fa 74 c6 45 fb 2e c6 45 fc 65 c6 45 fd 78 c6 45 fe 65 89 b5 50 fe ff ff 90 00 } //01 00 
		$a_01_1 = {4d 6d 4d 61 70 4c 6f 63 6b 65 64 50 61 67 65 73 53 70 65 63 69 66 79 43 61 63 68 65 } //01 00 
		$a_01_2 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //01 00 
		$a_01_3 = {4f 62 66 44 65 72 65 66 65 72 65 6e 63 65 4f 62 6a 65 63 74 } //00 00 
	condition:
		any of ($a_*)
 
}