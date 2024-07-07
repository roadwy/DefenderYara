
rule Trojan_O97M_Kerdown_D{
	meta:
		description = "Trojan:O97M/Kerdown.D,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {20 26 20 22 5c 6d 73 6f 68 74 6d 6c 2e 65 78 65 22 } //1  & "\msohtml.exe"
		$a_01_1 = {20 26 20 22 20 2f 2f 45 3a 76 62 73 63 72 69 70 74 20 2f 62 20 22 20 26 20 } //1  & " //E:vbscript /b " & 
		$a_01_2 = {20 26 20 22 5c 6d 73 6f 68 74 6d 6c 2e 6c 6f 67 22 } //1  & "\msohtml.log"
		$a_01_3 = {3d 20 22 48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 43 6c 61 73 73 65 73 5c 43 4c 53 49 44 5c 7b 22 } //1 = "HKCU\Software\Classes\CLSID\{"
		$a_01_4 = {26 20 22 7d 5c 53 68 65 6c 6c 5c 4d 61 6e 61 67 65 5c 43 6f 6d 6d 61 6e 64 5c 22 } //1 & "}\Shell\Manage\Command\"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}