
rule TrojanDownloader_Win32_Cutwail_AJ{
	meta:
		description = "TrojanDownloader:Win32/Cutwail.AJ,SIGNATURE_TYPE_PEHSTR_EXT,32 00 1e 00 06 00 00 "
		
	strings :
		$a_00_0 = {5c 5c 2e 5c 6e 64 69 73 5f 76 65 72 32 } //10 \\.\ndis_ver2
		$a_00_1 = {6e 65 74 73 68 20 66 69 72 65 77 61 6c 6c 20 73 65 74 20 61 6c 6c 6f 77 65 64 70 72 6f 67 72 61 6d 20 22 25 73 22 20 45 4e 41 42 4c 45 } //10 netsh firewall set allowedprogram "%s" ENABLE
		$a_00_2 = {43 6f 6d 53 70 65 63 00 20 3e 3e 20 4e 55 4c 00 2f 63 20 64 65 6c 20 } //10
		$a_00_3 = {47 45 54 20 2f 34 30 } //10 GET /40
		$a_02_4 = {68 eb 00 00 00 50 e8 90 01 02 ff ff 6a 05 50 e8 90 01 02 ff ff 6a 05 68 90 00 } //20
		$a_01_5 = {80 78 50 69 8d 4e 0c 51 8d 4e 08 51 75 0b } //20
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_02_4  & 1)*20+(#a_01_5  & 1)*20) >=30
 
}