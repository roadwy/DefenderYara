
rule Backdoor_Win32_Ppdoor_AV{
	meta:
		description = "Backdoor:Win32/Ppdoor.AV,SIGNATURE_TYPE_PEHSTR_EXT,52 00 52 00 0c 00 00 0a 00 "
		
	strings :
		$a_01_0 = {2a 2a 2a 20 50 52 4f 43 45 53 53 49 4e 47 20 55 50 44 41 54 45 } //0a 00  *** PROCESSING UPDATE
		$a_01_1 = {2a 2a 2a 20 66 61 69 6c 65 64 20 74 6f 20 64 6f 77 6e 6c 6f 61 64 20 68 74 74 70 20 64 61 74 61 } //0a 00  *** failed to download http data
		$a_01_2 = {2a 2a 2a 20 57 61 72 69 6e 69 67 21 20 5a 65 72 6f 20 74 68 72 65 61 64 21 } //0a 00  *** Warinig! Zero thread!
		$a_01_3 = {41 76 61 69 6c 61 62 6c 65 20 63 6f 6d 6d 61 6e 64 73 3a } //0a 00  Available commands:
		$a_01_4 = {67 65 74 5f 64 72 69 76 65 73 28 29 20 72 65 63 65 69 76 65 64 } //0a 00  get_drives() received
		$a_01_5 = {72 75 6e 5f 66 69 6c 65 28 29 2e 2e 2e } //0a 00  run_file()...
		$a_00_6 = {53 52 56 5f } //0a 00  SRV_
		$a_02_7 = {8b c2 83 c4 08 2d e9 03 00 00 0f 84 d7 00 00 00 48 0f 84 9c 00 00 00 48 0f 85 d6 00 00 00 55 68 90 01 04 e8 90 01 04 a1 90 01 04 83 c4 04 33 ed 85 c0 74 65 bf 90 01 04 53 8b 1d 90 01 04 8b f7 8b c5 b9 05 00 00 00 99 f7 f9 85 d2 75 25 81 fe 90 01 04 74 0d 8d 54 24 10 52 e8 90 01 02 ff ff 83 c4 04 8d 44 24 10 68 90 01 04 50 ff 15 90 01 04 8b 0f 8d 54 24 10 51 52 ff d3 90 00 } //01 00 
		$a_00_8 = {61 76 70 33 32 } //01 00  avp32
		$a_00_9 = {63 61 2e 65 78 65 } //01 00  ca.exe
		$a_00_10 = {70 61 76 73 72 76 } //01 00  pavsrv
		$a_00_11 = {61 76 67 75 61 72 64 2e 65 78 65 } //00 00  avguard.exe
	condition:
		any of ($a_*)
 
}