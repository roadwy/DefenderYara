
rule Trojan_Win32_AutoitInject_BI_MTB{
	meta:
		description = "Trojan:Win32/AutoitInject.BI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,33 00 33 00 07 00 00 "
		
	strings :
		$a_80_0 = {77 69 6e 72 61 72 73 66 78 6d 61 70 70 69 6e 67 66 69 6c 65 2e 74 6d 70 } //winrarsfxmappingfile.tmp  10
		$a_80_1 = {47 45 54 50 41 53 53 57 4f 52 44 31 } //GETPASSWORD1  10
		$a_80_2 = {5f 5f 74 6d 70 5f 72 61 72 5f 73 66 78 5f 61 63 63 65 73 73 5f 63 68 65 63 6b 5f 25 75 } //__tmp_rar_sfx_access_check_%u  10
		$a_02_3 = {53 65 74 75 70 3d [0-0a] 2e 76 62 73 } //1
		$a_02_4 = {53 65 74 75 70 3d [0-0a] 2e 76 62 65 } //1
		$a_80_5 = {50 61 74 68 3d 25 74 65 6d 70 25 5c } //Path=%temp%\  10
		$a_80_6 = {41 52 61 72 48 74 6d 6c 43 6c 61 73 73 4e 61 6d 65 } //ARarHtmlClassName  10
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*10+(#a_80_2  & 1)*10+(#a_02_3  & 1)*1+(#a_02_4  & 1)*1+(#a_80_5  & 1)*10+(#a_80_6  & 1)*10) >=51
 
}