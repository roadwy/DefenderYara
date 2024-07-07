
rule TrojanDownloader_Win32_Matcash_B{
	meta:
		description = "TrojanDownloader:Win32/Matcash.B,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 09 00 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //1 http\shell\open\command
		$a_00_1 = {48 6f 6c 6d 65 73 2e 63 00 00 00 00 6d 2f 31 37 50 } //1
		$a_00_2 = {48 6f 6c 00 6d 2f 31 37 50 00 } //1 潈l⽭㜱P
		$a_00_3 = {2e 77 72 73 2e 6d 00 00 68 74 74 70 3a 2f 2f } //1
		$a_00_4 = {5c 31 37 50 48 6f 6c 6d 65 73 00 } //1
		$a_00_5 = {63 6f 6e 74 65 6e 74 00 00 00 00 00 61 66 66 49 44 } //1
		$a_00_6 = {61 74 00 00 75 6e 2e 62 00 } //1
		$a_00_7 = {81 ec a4 00 00 00 89 8d 5c ff ff ff c7 85 74 ff ff ff 10 00 00 00 c6 85 78 ff ff ff } //1
		$a_02_8 = {6a 05 8d 85 90 01 02 ff ff 68 90 01 02 40 00 50 ff d7 83 c4 0c 85 c0 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_02_8  & 1)*1) >=5
 
}