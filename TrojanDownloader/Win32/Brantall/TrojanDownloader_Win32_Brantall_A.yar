
rule TrojanDownloader_Win32_Brantall_A{
	meta:
		description = "TrojanDownloader:Win32/Brantall.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 08 00 00 02 00 "
		
	strings :
		$a_02_0 = {3c 43 41 4d 50 41 49 47 4e 5f 49 44 3e 3c 21 5b 43 44 41 54 41 5b 90 02 04 5d 5d 3e 3c 2f 43 41 4d 50 41 49 47 4e 5f 49 44 3e 3c 43 41 4d 50 41 49 47 4e 5f 53 55 42 49 44 3e 3c 21 5b 43 44 41 54 41 5b 90 00 } //02 00 
		$a_00_1 = {25 00 73 00 3f 00 63 00 6d 00 70 00 3d 00 25 00 73 00 26 00 73 00 75 00 62 00 3d 00 25 00 73 00 26 00 72 00 6b 00 65 00 79 00 3d 00 25 00 73 00 } //01 00  %s?cmp=%s&sub=%s&rkey=%s
		$a_00_2 = {2f 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 65 00 72 00 2f 00 62 00 6f 00 6f 00 74 00 73 00 74 00 72 00 61 00 70 00 2e 00 70 00 68 00 70 00 } //01 00  /installer/bootstrap.php
		$a_01_3 = {49 00 42 00 55 00 70 00 64 00 61 00 74 00 65 00 72 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 } //01 00  IBUpdaterService
		$a_00_4 = {69 73 5f 63 6f 6d 70 6f 6e 65 6e 74 5f 6f 66 66 65 72 65 64 } //01 00  is_component_offered
		$a_00_5 = {67 65 74 5f 63 6f 6d 70 6f 6e 65 6e 74 5f 65 78 65 5f 6e 61 6d 65 } //01 00  get_component_exe_name
		$a_00_6 = {67 65 74 5f 63 61 6d 70 61 69 67 6e 5f 69 64 } //01 00  get_campaign_id
		$a_00_7 = {63 6f 6d 70 6f 6e 65 6e 74 5f 73 65 72 76 69 63 65 40 40 } //00 00  component_service@@
	condition:
		any of ($a_*)
 
}