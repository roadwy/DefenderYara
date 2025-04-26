
rule TrojanDownloader_O97M_IcedID_AII_MTB{
	meta:
		description = "TrojanDownloader:O97M/IcedID.AII!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {50 75 62 6c 69 63 20 53 75 62 20 43 6f 6d 6d 61 6e 64 42 75 74 74 6f 6e 31 5f 43 6c 69 63 6b 28 29 } //1 Public Sub CommandButton1_Click()
		$a_01_1 = {2e 65 78 65 63 20 66 72 6d 2e 43 6f 6d 6d 61 6e 64 42 75 74 74 6f 6e 31 2e 54 61 67 20 26 20 22 20 63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 6d 61 69 6e 2e 68 74 61 22 } //1 .exec frm.CommandButton1.Tag & " c:\users\public\main.hta"
		$a_01_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 22 20 26 20 73 63 72 69 70 74 20 26 20 22 73 68 65 6c 6c 22 29 } //1 = CreateObject("w" & script & "shell")
		$a_01_3 = {43 61 6c 6c 20 66 72 6d 2e 43 6f 6d 6d 61 6e 64 42 75 74 74 6f 6e 31 5f 43 6c 69 63 6b } //1 Call frm.CommandButton1_Click
		$a_01_4 = {2e 41 70 70 65 6e 64 5f 33 20 22 3c 64 69 76 20 69 64 3d 27 63 6f 6e 74 65 6e 74 27 3e 66 54 74 6c } //1 .Append_3 "<div id='content'>fTtl
		$a_01_5 = {73 70 6c 69 74 28 27 27 29 2e 72 65 76 65 72 73 65 28 29 2e 6a 6f 69 6e } //1 split('').reverse().join
		$a_01_6 = {54 69 6d 65 6f 75 74 20 3d 20 36 30 30 30 30 } //1 Timeout = 60000
		$a_01_7 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 } //1 Sub autoopen()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}