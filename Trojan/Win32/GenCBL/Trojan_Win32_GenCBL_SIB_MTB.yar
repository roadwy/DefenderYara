
rule Trojan_Win32_GenCBL_SIB_MTB{
	meta:
		description = "Trojan:Win32/GenCBL.SIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,5f 00 37 00 15 00 00 "
		
	strings :
		$a_80_0 = {69 74 64 6f 77 6e 6c 6f 61 64 2e 64 6c 6c } //itdownload.dll  20
		$a_80_1 = {2e 63 6f 6d 2f 70 77 72 61 70 2e 65 78 65 } //.com/pwrap.exe  20
		$a_80_2 = {41 70 70 20 4d 61 6e 61 67 65 72 5c 41 70 70 20 4d 61 6e 61 67 65 72 2e 65 78 65 } //App Manager\App Manager.exe  20
		$a_80_3 = {41 70 70 20 4d 61 6e 61 67 65 72 5c 70 77 72 61 70 2e 65 78 65 } //App Manager\pwrap.exe  20
		$a_80_4 = {69 74 64 5f 63 61 6e 63 65 6c } //itd_cancel  1
		$a_80_5 = {69 74 64 5f 63 6c 65 61 72 66 69 6c 65 73 } //itd_clearfiles  1
		$a_80_6 = {69 74 64 5f 64 6f 77 6e 6c 6f 61 64 66 69 6c 65 } //itd_downloadfile  1
		$a_80_7 = {69 74 64 5f 67 65 74 72 65 73 75 6c 74 6c 65 6e } //itd_getresultlen  1
		$a_80_8 = {69 74 64 5f 67 65 74 72 65 73 75 6c 74 73 74 72 69 6e 67 } //itd_getresultstring  1
		$a_80_9 = {69 74 64 5f 69 6e 69 74 75 69 } //itd_initui  1
		$a_80_10 = {69 74 64 5f 6c 6f 61 64 73 74 72 69 6e 67 73 } //itd_loadstrings  1
		$a_80_11 = {69 74 64 5f 73 65 74 6f 70 74 69 6f 6e } //itd_setoption  1
		$a_80_12 = {69 74 64 5f 67 65 74 66 69 6c 65 73 69 7a 65 } //itd_getfilesize  1
		$a_80_13 = {69 74 64 5f 67 65 74 73 74 72 69 6e 67 } //itd_getstring  1
		$a_80_14 = {69 74 64 5f 67 65 74 6f 70 74 69 6f 6e } //itd_getoption  1
		$a_80_15 = {69 74 64 5f 73 65 74 73 74 72 69 6e 67 } //itd_setstring  1
		$a_80_16 = {69 74 64 5f 61 64 64 66 69 6c 65 } //itd_addfile  1
		$a_80_17 = {69 74 64 5f 61 64 64 6d 69 72 72 6f 72 } //itd_addmirror  1
		$a_80_18 = {69 74 64 5f 61 64 64 66 69 6c 65 73 69 7a 65 } //itd_addfilesize  1
		$a_80_19 = {69 74 64 5f 64 6f 77 6e 6c 6f 61 64 66 69 6c 65 73 } //itd_downloadfiles  1
		$a_80_20 = {69 74 64 5f 66 69 6c 65 63 6f 75 6e 74 } //itd_filecount  1
	condition:
		((#a_80_0  & 1)*20+(#a_80_1  & 1)*20+(#a_80_2  & 1)*20+(#a_80_3  & 1)*20+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1+(#a_80_12  & 1)*1+(#a_80_13  & 1)*1+(#a_80_14  & 1)*1+(#a_80_15  & 1)*1+(#a_80_16  & 1)*1+(#a_80_17  & 1)*1+(#a_80_18  & 1)*1+(#a_80_19  & 1)*1+(#a_80_20  & 1)*1) >=55
 
}