
rule Backdoor_Win32_Fynloski_A{
	meta:
		description = "Backdoor:Win32/Fynloski.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 03 00 "
		
	strings :
		$a_01_0 = {44 43 50 45 52 53 46 57 42 50 } //03 00  DCPERSFWBP
		$a_03_1 = {49 5f 41 4d 5f 44 54 90 12 09 00 90 02 19 4b 6c 6f 67 2e 64 61 74 90 00 } //01 00 
		$a_03_2 = {68 24 59 47 00 68 34 59 47 00 e8 90 01 04 50 e8 90 00 } //01 00 
		$a_03_3 = {68 fc 52 47 00 68 0c 53 47 00 e8 90 01 04 50 e8 90 00 } //01 00 
		$a_01_4 = {5a 59 59 64 89 10 68 30 58 47 00 } //01 00 
		$a_01_5 = {5a 59 59 64 89 10 68 4d 52 47 00 } //00 00 
		$a_00_6 = {78 59 } //01 00  xY
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Fynloski_A_2{
	meta:
		description = "Backdoor:Win32/Fynloski.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 04 00 0d 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b 06 83 f8 2e 0f 8f 90 01 02 00 00 0f 84 90 01 02 00 00 83 c0 f8 83 f8 25 0f 87 90 01 02 00 00 ff 24 90 00 } //02 00 
		$a_01_1 = {81 7d a4 de ca de 43 0f 85 } //02 00 
		$a_03_2 = {c6 04 18 e9 8b 4d 90 01 01 8b c1 33 d2 52 50 8b c3 99 03 04 24 13 54 24 04 83 c4 08 83 c0 01 83 d2 00 2b f1 83 ee 05 90 00 } //02 00 
		$a_03_3 = {68 7f 74 04 40 8b 45 fc 50 e8 90 01 04 40 0f 84 90 01 02 00 00 8b 45 f8 b9 4c 00 00 00 99 f7 f9 48 85 c0 0f 8c 90 00 } //02 00 
		$a_01_4 = {23 62 6f 74 43 6f 6d 6d 61 6e 64 25 } //01 00  #botCommand%
		$a_01_5 = {50 6f 72 74 53 63 61 6e 41 64 64 } //01 00  PortScanAdd
		$a_01_6 = {52 50 43 4c 61 6e 53 63 61 6e } //01 00  RPCLanScan
		$a_01_7 = {57 69 6e 64 6f 77 73 4c 69 76 65 3a 6e 61 6d 65 3d 2a } //01 00  WindowsLive:name=*
		$a_01_8 = {44 44 4f 53 48 54 54 50 46 4c 4f 4f 44 } //01 00  DDOSHTTPFLOOD
		$a_01_9 = {44 44 4f 53 53 59 4e 46 4c 4f 4f 44 } //01 00  DDOSSYNFLOOD
		$a_01_10 = {44 44 4f 53 55 44 50 46 4c 4f 4f 44 } //01 00  DDOSUDPFLOOD
		$a_01_11 = {41 63 74 69 76 65 4f 66 66 6c 69 6e 65 4b 65 79 6c 6f 67 67 65 72 } //f6 ff  ActiveOfflineKeylogger
		$a_01_12 = {43 6f 6d 65 74 20 52 41 54 20 4c 65 67 61 63 79 20 69 73 20 61 6c 72 65 61 64 79 20 61 63 74 69 76 65 20 69 6e 20 79 6f 75 72 20 73 79 73 74 65 6d } //00 00  Comet RAT Legacy is already active in your system
	condition:
		any of ($a_*)
 
}