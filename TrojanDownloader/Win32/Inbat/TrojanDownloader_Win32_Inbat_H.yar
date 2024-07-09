
rule TrojanDownloader_Win32_Inbat_H{
	meta:
		description = "TrojanDownloader:Win32/Inbat.H,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {63 6e 7a 7a 2e 73 6a 74 38 2e 63 6f 6d 2f 69 6e 66 6f 2e 61 63 63 65 73 73 2f 3f 73 74 61 74 5f 25 76 61 72 25 } //1 cnzz.sjt8.com/info.access/?stat_%var%
		$a_00_1 = {64 65 6c 20 25 4d 59 46 49 4c 45 53 25 20 2f 66 20 2f 73 20 2f 71 } //1 del %MYFILES% /f /s /q
		$a_00_2 = {64 65 6c 20 22 25 41 4c 4c 55 53 45 52 53 50 52 4f 46 49 4c 45 25 5c a1 b8 bf aa ca bc a1 b9 b2 cb b5 a5 5c b3 cc d0 f2 5c c6 f4 b6 af 5c 2a 2e 2a 22 } //1
		$a_02_3 = {64 65 6c 20 22 43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c [0-06] 5c 75 6e 69 6e 73 30 30 30 2e 65 78 65 22 20 2f 66 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1) >=4
 
}