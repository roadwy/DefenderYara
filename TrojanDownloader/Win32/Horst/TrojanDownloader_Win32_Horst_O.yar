
rule TrojanDownloader_Win32_Horst_O{
	meta:
		description = "TrojanDownloader:Win32/Horst.O,SIGNATURE_TYPE_PEHSTR_EXT,ffffffd3 00 ffffffd3 00 05 00 00 0a 00 "
		
	strings :
		$a_00_0 = {75 70 73 65 65 6b 2e 6f 72 67 } //01 00  upseek.org
		$a_01_1 = {30 46 41 37 32 38 43 45 2d 35 35 45 36 2d 41 33 45 44 2d 42 42 33 31 2d 33 30 33 41 43 31 46 45 45 30 31 42 } //01 00  0FA728CE-55E6-A3ED-BB31-303AC1FEE01B
		$a_01_2 = {45 30 34 38 33 46 41 38 2d 43 45 41 33 2d 30 32 39 36 2d 42 41 42 43 2d 35 33 42 45 46 46 31 37 34 36 41 43 } //64 00  E0483FA8-CEA3-0296-BABC-53BEFF1746AC
		$a_01_3 = {43 72 65 61 74 65 4d 75 74 65 78 41 } //64 00  CreateMutexA
		$a_01_4 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //00 00  InternetOpenUrlA
	condition:
		any of ($a_*)
 
}