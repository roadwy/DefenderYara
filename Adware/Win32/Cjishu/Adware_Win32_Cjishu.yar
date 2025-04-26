
rule Adware_Win32_Cjishu{
	meta:
		description = "Adware:Win32/Cjishu,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_80_0 = {61 70 69 2e 6c 6d 69 66 65 6e 67 2e 63 6f 6d } //api.lmifeng.com  1
		$a_80_1 = {53 6f 66 74 77 61 72 65 5c 69 50 64 66 52 65 61 64 65 72 } //Software\iPdfReader  1
		$a_80_2 = {53 6f 66 74 77 61 72 65 5c 69 48 75 59 61 } //Software\iHuYa  1
		$a_80_3 = {61 69 79 61 73 75 6f 2e 63 6e } //aiyasuo.cn  1
		$a_80_4 = {73 68 6f 77 2e 67 2e 6d 65 64 69 61 76 2e 63 6f 6d } //show.g.mediav.com  1
		$a_80_5 = {50 65 65 6b 4d 65 73 73 61 67 65 57 } //PeekMessageW  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=4
 
}
rule Adware_Win32_Cjishu_2{
	meta:
		description = "Adware:Win32/Cjishu,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 08 00 00 "
		
	strings :
		$a_80_0 = {69 70 64 66 72 65 61 64 2e 65 78 65 } //ipdfread.exe  1
		$a_80_1 = {69 70 64 66 72 65 61 64 65 72 74 6f 6f 6c 73 } //ipdfreadertools  1
		$a_80_2 = {6d 69 6e 69 2e 6c 6d 69 66 65 6e 67 2e 63 6f 6d } //mini.lmifeng.com  1
		$a_80_3 = {69 70 64 66 72 65 61 64 65 72 74 6f 6f 6c 73 41 70 70 } //ipdfreadertoolsApp  1
		$a_80_4 = {53 6f 66 74 77 61 72 65 5c 69 50 64 66 52 65 61 64 65 72 5c } //Software\iPdfReader\  1
		$a_80_5 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_6 = {55 6e 69 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //Uninstaller.exe  -100
		$a_80_7 = {55 6e 69 6e 73 74 61 6c 2e 65 78 65 } //Uninstal.exe  -100
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*-100+(#a_80_6  & 1)*-100+(#a_80_7  & 1)*-100) >=5
 
}