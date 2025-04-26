
rule Trojan_Win32_Startpage_UG{
	meta:
		description = "Trojan:Win32/Startpage.UG,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 33 36 30 73 65 55 52 4c } //1 \360seURL
		$a_01_1 = {5c 64 61 6f 2e 69 63 6f } //1 \dao.ico
		$a_01_2 = {53 74 61 72 74 20 50 61 67 65 } //1 Start Page
		$a_01_3 = {5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 2e 6c 6e 6b } //1 \Internet Explorer.lnk
		$a_01_4 = {61 48 52 30 63 44 6f 76 4c 33 64 33 64 79 } //1 aHR0cDovL3d3dy
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}