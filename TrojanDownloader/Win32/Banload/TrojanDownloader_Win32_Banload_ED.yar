
rule TrojanDownloader_Win32_Banload_ED{
	meta:
		description = "TrojanDownloader:Win32/Banload.ED,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 09 00 00 "
		
	strings :
		$a_00_0 = {55 8b ec 83 c4 f8 53 56 57 89 55 f8 89 45 fc 8b 45 fc e8 15 22 fb ff 8b 45 f8 e8 0d 22 fb ff 33 c0 55 68 5e 21 45 00 64 ff 30 64 89 20 33 c0 55 68 37 21 45 00 64 ff 30 64 89 20 6a 00 6a 00 8b 45 f8 e8 f5 21 fb ff 50 8b 45 fc e8 ec 21 fb ff 50 6a 00 e8 68 40 fd ff 85 c0 0f 94 c3 33 c0 5a 59 59 64 89 10 eb 0c e9 60 14 fb ff 33 db e8 c1 17 fb ff 33 c0 5a 59 59 64 89 10 68 65 21 45 00 8d 45 f8 ba 02 00 00 00 e8 13 1d fb ff c3 e9 ed 16 fb ff eb eb 8b c3 5f 5e 5b 59 59 5d c3 } //10
		$a_00_1 = {55 8b ec 81 c4 f4 f7 ff ff 89 55 f8 89 45 fc 8b 45 fc e8 75 21 fb ff 8b 45 f8 e8 6d 21 fb ff 33 c0 55 68 ef 21 45 00 64 ff 30 64 89 20 8d 85 f7 fb ff ff 8b 55 fc e8 f5 61 fb ff 8d 85 f6 f7 ff ff 8b 55 f8 e8 e7 61 fb ff 6a 00 6a 00 8d 85 f6 f7 ff ff 50 8d 85 f7 fb ff ff 50 6a 00 6a 00 e8 0c 3f fd ff 33 c0 5a 59 59 64 89 10 68 f6 21 45 00 8d 45 f8 ba 02 00 00 00 e8 82 1c fb ff c3 e9 5c 16 fb ff eb eb 8b e5 5d c3 } //10
		$a_03_2 = {16 00 00 00 43 3a 5c 57 69 6e 64 6f 77 73 5c 73 70 6f 6f 6c (73|75) 76 2e 65 78 65 00 } //1
		$a_03_3 = {18 00 00 00 68 74 74 70 3a 2f 2f 77 77 77 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2e 62 72 00 00 00 00 ff ff ff ff ?? 00 00 00 43 3a 5c 57 69 6e 64 6f 77 73 5c } //1
		$a_01_4 = {43 3a 5c 43 6f 6e 74 61 63 74 73 4d 53 4e 2e 65 78 65 00 } //1
		$a_01_5 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 72 65 67 73 76 72 33 32 2e 65 78 65 00 } //1 㩃坜湩潤獷牜来癳㍲⸲硥e
		$a_03_6 = {43 3a 5c 66 69 6c 65 2e 65 78 65 00 ff ff ff ff ?? 00 00 00 68 74 74 70 3a 2f 2f } //1
		$a_01_7 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 6d 73 77 6f 72 64 33 32 2e 65 78 65 00 } //1 㩃坜湩潤獷浜睳牯㍤⸲硥e
		$a_01_8 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 6c 6f 73 74 65 72 2e 65 78 65 00 } //1
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_03_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=21
 
}