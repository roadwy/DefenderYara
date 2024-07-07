
rule Trojan_BAT_XpertRat_MA_MTB{
	meta:
		description = "Trojan:BAT/XpertRat.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_81_1 = {47 65 74 54 79 70 65 73 } //1 GetTypes
		$a_80_2 = {68 74 74 70 73 3a 2f 2f 73 74 6f 72 65 32 2e 67 6f 66 69 6c 65 2e 69 6f 2f 64 6f 77 6e 6c 6f 61 64 2f 36 35 38 38 38 34 64 61 2d 38 64 64 37 2d 34 37 38 31 2d 39 34 35 35 2d 38 61 61 66 36 31 66 63 62 32 34 34 2f 41 74 66 74 69 67 6b 76 71 73 63 70 76 2e 64 6c 6c } //https://store2.gofile.io/download/658884da-8dd7-4781-9455-8aaf61fcb244/Atftigkvqscpv.dll  1
		$a_81_3 = {55 74 69 74 65 71 7a 6c 6c 68 77 65 66 72 77 70 6a 79 61 } //1 Utiteqzllhwefrwpjya
		$a_81_4 = {73 65 74 5f 46 69 6c 65 4e 61 6d 65 } //1 set_FileName
		$a_81_5 = {53 74 61 72 74 2d 53 6c 65 65 70 20 2d 53 65 63 6f 6e 64 73 } //1 Start-Sleep -Seconds
		$a_81_6 = {4c 6f 67 69 6e 53 74 61 74 75 73 } //1 LoginStatus
		$a_81_7 = {43 61 6c 6c 4e 65 78 74 48 6f 6f 6b 45 78 } //1 CallNextHookEx
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_80_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}