
rule Trojan_Win32_Nanocore_BE_MTB{
	meta:
		description = "Trojan:Win32/Nanocore.BE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,79 00 79 00 0e 00 00 "
		
	strings :
		$a_80_0 = {77 69 6e 72 61 72 73 66 78 6d 61 70 70 69 6e 67 66 69 6c 65 2e 74 6d 70 } //winrarsfxmappingfile.tmp  10
		$a_80_1 = {47 45 54 50 41 53 53 57 4f 52 44 31 } //GETPASSWORD1  10
		$a_80_2 = {5f 5f 74 6d 70 5f 72 61 72 5f 73 66 78 5f 61 63 63 65 73 73 5f 63 68 65 63 6b 5f 25 75 } //__tmp_rar_sfx_access_check_%u  10
		$a_80_3 = {2e 64 6f 63 78 } //.docx  10
		$a_80_4 = {2e 70 70 74 } //.ppt  10
		$a_80_5 = {2e 69 63 6d } //.icm  1
		$a_80_6 = {2e 63 70 6c } //.cpl  1
		$a_80_7 = {2e 6d 70 33 } //.mp3  10
		$a_80_8 = {2e 70 64 66 } //.pdf  10
		$a_80_9 = {2e 6d 73 63 } //.msc  10
		$a_80_10 = {45 78 74 72 61 63 74 69 6e 67 20 66 69 6c 65 73 20 74 6f 20 43 3a 5c 20 66 6f 6c 64 65 72 } //Extracting files to C:\ folder  10
		$a_80_11 = {50 61 74 68 3d 25 74 65 6d 70 25 5c } //Path=%temp%\  10
		$a_80_12 = {41 52 61 72 48 74 6d 6c 43 6c 61 73 73 4e 61 6d 65 } //ARarHtmlClassName  10
		$a_80_13 = {43 72 79 70 74 50 72 6f 74 65 63 74 4d 65 6d 6f 72 79 20 66 61 69 6c 65 64 } //CryptProtectMemory failed  10
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*10+(#a_80_2  & 1)*10+(#a_80_3  & 1)*10+(#a_80_4  & 1)*10+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*10+(#a_80_8  & 1)*10+(#a_80_9  & 1)*10+(#a_80_10  & 1)*10+(#a_80_11  & 1)*10+(#a_80_12  & 1)*10+(#a_80_13  & 1)*10) >=121
 
}