
rule Ransom_Win32_SnatchGolang_NVR_MTB{
	meta:
		description = "Ransom:Win32/SnatchGolang.NVR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_80_0 = {52 45 41 44 4d 45 5f 35 4f 41 58 4e 5f 44 41 54 41 2e 74 78 74 } //README_5OAXN_DATA.txt  01 00 
		$a_80_1 = {59 6f 75 20 6d 61 79 20 62 65 20 61 20 76 69 63 74 69 6d 20 6f 66 20 66 72 61 75 64 2e } //You may be a victim of fraud.  01 00 
		$a_80_2 = {54 6f 20 70 72 6f 76 65 20 74 68 61 74 20 49 20 63 61 6e 20 72 65 63 6f 76 65 72 20 79 6f 75 72 20 66 69 6c 65 73 2c 20 49 20 61 6d 20 72 65 61 64 79 20 74 6f 20 64 65 63 72 79 70 74 20 61 6e 79 20 74 68 72 65 65 20 66 69 6c 65 73 20 66 6f 72 20 66 72 65 65 20 28 65 78 63 65 70 74 20 64 61 74 61 62 61 73 65 73 2c 20 45 78 63 65 6c 20 61 6e 64 20 62 61 63 6b 75 70 73 29 } //To prove that I can recover your files, I am ready to decrypt any three files for free (except databases, Excel and backups)  01 00 
		$a_80_3 = {2f 72 6f 6f 74 2f 67 6f 2f 73 72 63 2f 73 6e 61 74 63 68 2f 63 6f 6e 66 69 67 2e 67 6f } ///root/go/src/snatch/config.go  01 00 
		$a_80_4 = {2f 72 6f 6f 74 2f 67 6f 2f 73 72 63 2f 73 6e 61 74 63 68 2f 73 65 72 76 69 63 65 73 2e 67 6f } ///root/go/src/snatch/services.go  01 00 
		$a_80_5 = {2f 72 6f 6f 74 2f 67 6f 2f 73 72 63 2f 73 6e 61 74 63 68 2f 6d 61 69 6e 2e 67 6f } ///root/go/src/snatch/main.go  01 00 
		$a_80_6 = {2f 72 6f 6f 74 2f 67 6f 2f 73 72 63 2f 73 6e 61 74 63 68 2f 6c 6f 67 65 72 2e 67 6f } ///root/go/src/snatch/loger.go  01 00 
		$a_80_7 = {2f 72 6f 6f 74 2f 67 6f 2f 73 72 63 2f 73 6e 61 74 63 68 2f 66 69 6c 65 73 2e 67 6f } ///root/go/src/snatch/files.go  01 00 
		$a_80_8 = {2f 72 6f 6f 74 2f 67 6f 2f 73 72 63 2f 73 6e 61 74 63 68 2f 64 69 72 73 2e 67 6f } ///root/go/src/snatch/dirs.go  00 00 
	condition:
		any of ($a_*)
 
}