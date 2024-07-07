
rule TrojanDownloader_Win32_QQHelper_RE{
	meta:
		description = "TrojanDownloader:Win32/QQHelper.RE,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 50 52 40 43 5a 58 8b 4d 08 8a 01 84 c0 74 0c 2c 90 01 01 88 01 8a 41 01 41 84 c0 75 f4 e8 90 00 } //8
		$a_00_1 = {80 85 8a 8b 78 83 83 48 45 89 80 85 7e 4c 49 47 45 86 89 7e 46 82 82 82 82 46 84 84 80 85 8a 8b 78 83 83 45 7c 8f 7c 00 } //2
		$a_00_2 = {2f 6b 6b 6b 6b 2f 6d 6d 69 6e 73 74 61 6c 6c 2e 65 78 65 } //2 /kkkk/mminstall.exe
	condition:
		((#a_03_0  & 1)*8+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=10
 
}