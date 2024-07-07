
rule TrojanDownloader_Win32_Banload_ASZ{
	meta:
		description = "TrojanDownloader:Win32/Banload.ASZ,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {00 5c 72 65 73 6f 6c 76 65 72 2e 65 78 65 00 00 00 ff ff ff ff 06 00 00 00 2f 6e 6f 67 75 69 00 00 ff ff ff ff 09 00 00 00 5c 75 62 65 72 2e 74 78 74 00 } //5
		$a_02_1 = {5c 74 65 6d 70 2e 7a 69 70 00 00 00 ff ff ff ff 90 01 01 00 00 00 5c 90 02 0f 2e 65 78 65 90 02 03 00 ff ff ff ff 90 01 01 00 00 00 5c 6d 65 64 69 61 63 65 6e 74 90 02 03 2e 65 78 65 00 90 00 } //1
		$a_00_2 = {5c 74 65 6d 70 2e 7a 69 70 00 00 00 ff ff ff ff 11 00 00 00 5c 65 78 74 65 6e 73 6f 72 6a 61 76 61 2e 65 78 65 00 } //1
	condition:
		((#a_00_0  & 1)*5+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=6
 
}
rule TrojanDownloader_Win32_Banload_ASZ_2{
	meta:
		description = "TrojanDownloader:Win32/Banload.ASZ,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 08 00 00 "
		
	strings :
		$a_01_0 = {33 db 8a 5c 30 ff 33 5d e8 3b fb 7c 0a 81 c3 ff 00 00 00 2b df eb 02 2b df 8d 45 d4 8b d3 } //5
		$a_00_1 = {2e 62 61 74 00 00 00 00 ff ff ff ff 02 00 00 00 3a 31 00 00 ff ff ff ff 0a 00 00 00 65 72 61 73 65 20 22 25 73 22 } //1
		$a_00_2 = {49 66 20 65 78 69 73 74 20 22 25 73 22 20 47 6f 74 6f 20 31 } //1 If exist "%s" Goto 1
		$a_00_3 = {69 65 28 61 6c 28 22 25 73 22 2c 34 29 2c 22 61 6c 28 5c 22 25 30 3a 73 5c 22 2c 33 29 22 2c 22 6a 6b 28 5c 22 25 31 3a 73 5c 22 2c 5c 22 25 30 3a 73 5c 22 29 22 29 } //1 ie(al("%s",4),"al(\"%0:s\",3)","jk(\"%1:s\",\"%0:s\")")
		$a_01_4 = {7b 44 45 4c 45 54 45 7d } //1 {DELETE}
		$a_01_5 = {7b 50 47 44 4e 7d } //1 {PGDN}
		$a_01_6 = {7b 44 4f 57 4e 7d } //1 {DOWN}
		$a_01_7 = {7b 42 4b 53 50 7d } //1 {BKSP}
	condition:
		((#a_01_0  & 1)*5+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=11
 
}
rule TrojanDownloader_Win32_Banload_ASZ_3{
	meta:
		description = "TrojanDownloader:Win32/Banload.ASZ,SIGNATURE_TYPE_PEHSTR_EXT,ffffffd3 00 ffffffd3 00 06 00 00 "
		
	strings :
		$a_03_0 = {0f b6 44 30 ff 33 c3 89 45 90 01 01 3b 7d 90 01 01 7c 0f 8b 45 90 01 01 05 ff 00 00 00 2b c7 89 45 90 01 01 eb 03 29 7d 90 01 01 8d 45 90 01 01 8b 55 90 01 01 e8 90 01 04 8b 55 90 00 } //100
		$a_01_1 = {59 55 51 4c 32 33 4b 4c 32 33 44 46 39 30 57 49 35 45 31 4a 41 53 34 36 37 4e 4d 43 58 58 4c 36 4a 41 4f 41 55 57 57 4d 43 4c 30 41 4f 4d 4d } //100 YUQL23KL23DF90WI5E1JAS467NMCXXL6JAOAUWWMCL0AOMM
		$a_00_2 = {2e 62 61 74 00 00 00 00 ff ff ff ff 02 00 00 00 3a 31 00 00 ff ff ff ff 0a 00 00 00 65 72 61 73 65 20 22 25 73 22 } //10
		$a_00_3 = {49 66 20 65 78 69 73 74 20 22 25 73 22 20 47 6f 74 6f 20 31 } //10 If exist "%s" Goto 1
		$a_00_4 = {54 61 73 6b 62 61 72 43 72 65 61 74 65 64 } //1 TaskbarCreated
		$a_01_5 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c } //1 SOFTWARE\Borland\Delphi\
	condition:
		((#a_03_0  & 1)*100+(#a_01_1  & 1)*100+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1) >=211
 
}