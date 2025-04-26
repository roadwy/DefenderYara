
rule PWS_Win32_Lineage_gen_K{
	meta:
		description = "PWS:Win32/Lineage.gen!K,SIGNATURE_TYPE_PEHSTR_EXT,ffffff82 00 5a 00 13 00 00 "
		
	strings :
		$a_00_0 = {53 6f 66 74 77 61 72 65 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 4c 6f 63 61 6c 65 73 } //40 Software\Borland\Delphi\Locales
		$a_02_1 = {50 72 6f 78 79 2d 43 6f 6e 6e 65 63 74 69 6f 6e 3a 20 4b 65 65 70 2d 41 6c 69 76 65 [0-10] 55 8b ec 33 c0 55 68 [0-04] 64 ff 30 64 89 20 ff 05 [0-04] 33 c0 5a 59 59 64 89 10 68 48 } //20
		$a_00_2 = {41 63 63 65 70 74 3a 20 69 6d 61 67 65 2f 67 69 66 2c 20 69 6d 61 67 65 2f 78 2d 78 62 69 74 6d 61 70 2c 20 69 6d 61 67 65 2f 6a 70 65 67 2c 20 69 6d 61 67 65 2f 70 6a 70 65 67 2c 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 73 68 6f 63 6b 77 61 76 65 2d 66 6c 61 73 68 2c 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 76 6e 64 2e 6d 73 2d 70 6f 77 65 72 70 6f 69 6e 74 2c 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 76 6e 64 2e 6d 73 2d 65 78 63 65 6c 2c 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 6d 73 77 6f 72 64 } //20 Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/x-shockwave-flash, application/vnd.ms-powerpoint, application/vnd.ms-excel, application/msword
		$a_00_3 = {41 63 63 65 70 74 2d 4c 61 6e 67 75 61 67 65 3a 20 7a 68 2d 63 6e } //10 Accept-Language: zh-cn
		$a_00_4 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 36 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 35 2e 30 29 } //10 User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)
		$a_00_5 = {43 6f 6e 74 65 6e 74 2d 44 69 73 70 6f 73 69 74 69 6f 6e 3a 20 66 6f 72 6d 2d 64 61 74 61 3b 20 6e 61 6d 65 3d 22 66 69 6c 65 31 22 3b 20 66 69 6c 65 6e 61 6d 65 3d } //10 Content-Disposition: form-data; name="file1"; filename=
		$a_00_6 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 6f 63 68 64 } //10 Content-Type: application/ochd
		$a_00_7 = {6d 6f 64 69 66 79 67 73 20 6d 61 70 66 69 6c 65 } //10 modifygs mapfile
		$a_00_8 = {43 74 32 44 6c 6c 2e 64 6c 6c 00 48 6f 6f 6b 4f 66 66 00 48 6f 6f 6b 4f 6e } //10
		$a_00_9 = {68 74 74 70 3a 2f 2f 64 66 2e 68 61 6e 67 61 6d 65 2e 63 6f 6d 2f 3f 47 4f 3d 68 6f 6d 65 } //10 http://df.hangame.com/?GO=home
		$a_00_10 = {69 64 5f 68 69 64 64 65 6e 00 00 00 ff ff ff ff 09 00 00 00 70 61 73 73 77 6f 72 64 32 } //10
		$a_00_11 = {4b 65 79 48 6f 6f 6b 2e 64 6c 6c 00 4d 73 67 48 6f 6f 6b 4f 66 66 00 4d 73 67 48 6f 6f 6b 4f 6e } //10
		$a_02_12 = {63 3a 5c 31 2e 74 78 74 [0-10] 68 74 74 70 3a 2f 2f 64 66 2e 68 61 6e 67 61 6d 65 2e 63 6f 6d [0-10] 69 64 5f 68 69 64 64 65 6e } //10
		$a_00_13 = {44 4e 46 2e 65 78 65 } //10 DNF.exe
		$a_00_14 = {68 74 74 70 3a 2f 2f 77 77 77 2e 79 61 6d 73 67 61 6d 65 2e 63 6f 6d 2f 69 74 65 6d 62 61 79 2f 73 65 6e 64 6d 61 69 6c 2e 61 73 70 3f 74 6f 6d 61 69 6c 3d 77 64 6f } //10 http://www.yamsgame.com/itembay/sendmail.asp?tomail=wdo
		$a_00_15 = {2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 37 63 66 31 64 36 63 34 37 63 } //10 -----------------------------7cf1d6c47c
		$a_00_16 = {66 69 6c 65 20 6f 6e 65 20 63 6f 6e 74 65 6e 74 2e 20 43 6f 6e 74 61 6e 74 2d 54 79 70 65 20 63 61 6e 20 62 65 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 6f 63 74 65 74 2d 73 74 72 65 61 6d 20 6f 72 20 69 66 79 6f 75 20 77 61 6e 74 20 79 6f 75 20 63 61 6e 20 61 73 6b 20 79 6f 75 72 20 4f 53 20 66 6f 74 20 74 68 65 20 65 78 61 63 74 20 74 79 70 65 } //10 file one content. Contant-Type can be application/octet-stream or ifyou want you can ask your OS fot the exact type
		$a_00_17 = {68 74 74 70 3a 2f 2f 32 31 38 2e 33 36 2e 31 32 34 2e 34 31 2f 64 65 6d 6f 67 73 2f 64 65 6d 6f 2e 61 73 70 } //10 http://218.36.124.41/demogs/demo.asp
		$a_00_18 = {54 65 6e 63 65 6e 74 5f 54 72 61 76 65 6c 65 72 5f 4d 61 69 6e 5f 57 69 6e 64 6f 77 } //10 Tencent_Traveler_Main_Window
	condition:
		((#a_00_0  & 1)*40+(#a_02_1  & 1)*20+(#a_00_2  & 1)*20+(#a_00_3  & 1)*10+(#a_00_4  & 1)*10+(#a_00_5  & 1)*10+(#a_00_6  & 1)*10+(#a_00_7  & 1)*10+(#a_00_8  & 1)*10+(#a_00_9  & 1)*10+(#a_00_10  & 1)*10+(#a_00_11  & 1)*10+(#a_02_12  & 1)*10+(#a_00_13  & 1)*10+(#a_00_14  & 1)*10+(#a_00_15  & 1)*10+(#a_00_16  & 1)*10+(#a_00_17  & 1)*10+(#a_00_18  & 1)*10) >=90
 
}