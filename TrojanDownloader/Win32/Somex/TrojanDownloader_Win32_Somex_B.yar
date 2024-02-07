
rule TrojanDownloader_Win32_Somex_B{
	meta:
		description = "TrojanDownloader:Win32/Somex.B,SIGNATURE_TYPE_PEHSTR,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 73 5c 25 73 65 78 2e 64 6c 6c } //01 00  %s\%sex.dll
		$a_01_1 = {5c 73 79 73 74 65 6d 5c 63 6f 6e 66 69 67 5f 73 68 65 6e 67 68 61 69 2e 64 61 74 } //01 00  \system\config_shenghai.dat
		$a_01_2 = {53 65 72 76 69 63 65 44 6c 6c 20 2f 74 20 52 45 47 5f 45 58 50 41 4e 44 5f 53 5a 20 2f 64 20 25 73 } //01 00  ServiceDll /t REG_EXPAND_SZ /d %s
		$a_01_3 = {25 73 3f 61 63 74 69 6f 6e 3d 65 78 65 73 75 63 63 65 73 73 26 68 6f 73 74 69 64 3d 25 73 } //01 00  %s?action=exesuccess&hostid=%s
		$a_01_4 = {4f 75 74 54 69 6d 65 4f 66 59 65 61 72 } //00 00  OutTimeOfYear
	condition:
		any of ($a_*)
 
}