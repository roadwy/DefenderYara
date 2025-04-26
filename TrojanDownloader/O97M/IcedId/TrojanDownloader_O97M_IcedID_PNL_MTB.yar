
rule TrojanDownloader_O97M_IcedID_PNL_MTB{
	meta:
		description = "TrojanDownloader:O97M/IcedID.PNL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {2e 65 78 65 63 20 66 72 6d 2e 63 6d 64 42 75 74 74 6f 6e 31 2e 54 61 67 20 26 20 22 20 22 20 26 20 66 72 6d 2e 63 6d 64 42 75 74 74 6f 6e 31 2e 63 61 70 74 69 6f 6e } //1 .exec frm.cmdButton1.Tag & " " & frm.cmdButton1.caption
		$a_01_1 = {43 61 6c 6c 20 66 72 6d 2e 43 6f 6d 6d 61 6e 64 42 75 74 74 6f 6e 31 5f 43 6c 69 63 6b } //1 Call frm.CommandButton1_Click
		$a_01_2 = {3d 20 66 72 6d 2e 63 6d 64 42 75 74 74 6f 6e 31 2e 63 61 70 74 69 6f 6e } //1 = frm.cmdButton1.caption
		$a_01_3 = {2e 72 65 76 65 72 73 65 28 29 2e 6a 6f 69 6e 28 27 27 29 } //1 .reverse().join('')
		$a_01_4 = {2e 54 69 6d 65 6f 75 74 20 3d 20 36 30 30 30 30 } //1 .Timeout = 60000
		$a_01_5 = {58 4a 30 4f 79 6b 69 64 47 4e 6c 61 6d 4a 76 62 57 56 30 63 33 6c 7a 5a 57 78 70 5a 69 35 6e 62 6d 6c 30 63 47 6c 79 59 33 4d 69 4b 48 52 6a 5a } //1 XJ0OykidGNlamJvbWV0c3lzZWxpZi5nbml0cGlyY3MiKHRjZ
		$a_01_6 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 } //1 Sub autoopen()
		$a_01_7 = {73 70 6c 69 74 28 27 7c 27 29 3b 76 61 72 } //1 split('|');var
		$a_01_8 = {50 72 69 6e 74 20 23 31 } //1 Print #1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}