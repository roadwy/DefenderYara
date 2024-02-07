
rule Backdoor_Win32_Delf_ADH{
	meta:
		description = "Backdoor:Win32/Delf.ADH,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_02_0 = {55 8b ec 83 c4 c4 53 56 57 33 d2 89 55 c4 89 55 c8 89 55 d0 89 55 cc 89 55 d8 89 55 d4 89 45 fc 8b 45 fc e8 e4 b4 ff ff 33 c0 55 68 90 01 04 64 ff 30 64 89 20 8d 55 d4 b8 01 00 00 00 e8 35 fd ff ff ff 75 d4 ff 75 fc 68 90 01 04 8d 45 d8 ba 03 00 00 00 e8 25 b4 ff ff 8b 45 d8 e8 b9 b4 ff ff 8b f8 8d 55 cc 33 c0 e8 09 fd ff ff ff 75 cc ff 75 fc 68 90 01 04 8d 45 d0 ba 03 00 00 00 e8 f9 b3 ff ff 8b 45 d0 90 00 } //01 00 
		$a_02_1 = {e8 8d b4 ff ff 89 45 f8 68 3f 00 0f 00 6a 00 6a 00 e8 90 01 04 8b d8 85 db 0f 84 a0 00 00 00 68 ff 01 0f 00 8b 45 fc e8 65 b4 ff ff 50 53 e8 90 01 04 8b f0 85 f6 75 08 53 e8 90 01 04 eb 43 8d 45 dc 50 56 e8 90 01 04 85 c0 74 2f 83 7d e0 01 74 29 8d 45 dc 50 6a 01 56 e8 90 01 04 85 c0 74 19 eb 11 6a 0a e8 90 01 04 8d 45 dc 50 56 e8 90 01 04 83 7d e0 03 74 e9 56 e8 90 01 04 56 e8 90 01 04 53 e8 90 01 04 68 dc 05 00 00 e8 90 00 } //01 00 
		$a_01_2 = {43 6f 6e 74 72 6f 6c 53 65 72 76 69 63 65 } //01 00  ControlService
		$a_01_3 = {51 75 65 72 79 53 65 72 76 69 63 65 53 74 61 74 75 73 } //01 00  QueryServiceStatus
		$a_01_4 = {44 65 6c 65 74 65 53 65 72 76 69 63 65 } //01 00  DeleteService
		$a_00_5 = {73 76 63 68 6f 73 74 } //01 00  svchost
		$a_00_6 = {6b 65 72 6e 6c 33 32 } //00 00  kernl32
	condition:
		any of ($a_*)
 
}