
rule TrojanDownloader_Win64_GhostRAT_PAY_MTB{
	meta:
		description = "TrojanDownloader:Win64/GhostRAT.PAY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 8d 15 d9 82 24 00 48 8d 4c 24 38 e8 37 f0 ff ff 90 48 8d 15 bf 70 1b 00 48 8d 4c 24 60 e8 25 f0 ff ff 90 4c 8d 44 24 38 48 8d 54 24 60 48 8d 8c 24 90 00 00 00 e8 7d ed ff ff 90 48 8d 4c 24 60 e8 72 f0 ff ff 90 48 8d 4c 24 38 e8 67 f0 ff ff 48 8d 8c 24 90 00 00 00 e8 4a eb ff ff 4c 8d 05 5b 70 1b 00 48 8d 15 54 82 24 00 48 8d 0d 6d 82 24 00 e8 d0 fc ff ff 48 8d 15 41 82 24 00 48 8d 0d aa 70 1b 00 e8 dd fd ff ff c7 44 24 28 05 00 00 00 48 c7 44 24 20 00 00 00 00 4c 8d 0d 1c 70 1b 00 4c 8d 05 96 70 1b 00 48 8d 15 b7 70 1b 00 33 c9 ff 15 77 5a 1b 00 } //4
		$a_00_1 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 6b 69 6e 67 73 6f 66 74 2e 64 61 74 } //1 C:\Users\Public\kingsoft.dat
		$a_00_2 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 6d 61 63 66 65 65 2e 64 61 74 } //1 C:\Users\Public\macfee.dat
	condition:
		((#a_01_0  & 1)*4+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=6
 
}