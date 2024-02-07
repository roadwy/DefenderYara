
rule TrojanDownloader_Win32_Netins_A{
	meta:
		description = "TrojanDownloader:Win32/Netins.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_80_0 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 43 6f 6d 6d 6f 6e 20 46 69 6c 65 73 5c 25 49 36 34 75 2e 6a 70 67 } //C:\Program Files\Common Files\%I64u.jpg  01 00 
		$a_00_1 = {63 6f 75 6e 74 3d 25 64 7c 25 64 26 64 61 74 61 3d 25 73 26 63 6f 70 79 3d 25 73 26 69 6e 66 6f 3d 25 73 26 61 63 74 3d 64 65 62 75 67 } //01 00  count=%d|%d&data=%s&copy=%s&info=%s&act=debug
		$a_00_2 = {4e 65 74 49 6e 73 74 61 6c 6c 65 72 32 30 31 30 } //01 00  NetInstaller2010
		$a_00_3 = {4e 65 74 47 65 74 65 72 } //00 00  NetGeter
	condition:
		any of ($a_*)
 
}