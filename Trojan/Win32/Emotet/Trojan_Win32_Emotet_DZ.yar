
rule Trojan_Win32_Emotet_DZ{
	meta:
		description = "Trojan:Win32/Emotet.DZ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {61 66 74 65 72 69 6e 73 74 61 6e 63 65 73 74 61 62 6c 65 44 72 6f 70 62 6f 78 69 45 61 73 74 65 72 61 76 61 69 6c 61 62 6c 65 76 69 72 74 75 61 6c 66 69 72 73 74 } //1 afterinstancestableDropboxiEasteravailablevirtualfirst
		$a_01_1 = {68 77 69 74 68 75 70 64 61 74 65 73 2e 31 39 33 47 6f 6f 67 6c 65 44 6f 77 6e 6c 6f 61 64 65 64 6f 6e 65 43 30 63 6f 6f 72 64 69 6e 61 74 65 64 70 61 73 73 61 67 65 } //1 hwithupdates.193GoogleDownloadedoneC0coordinatedpassage
		$a_01_2 = {64 65 76 65 6c 6f 70 65 72 73 2c 74 6f 4e 54 68 65 79 53 } //1 developers,toNTheyS
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}