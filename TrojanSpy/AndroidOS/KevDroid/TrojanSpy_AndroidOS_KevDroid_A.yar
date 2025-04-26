
rule TrojanSpy_AndroidOS_KevDroid_A{
	meta:
		description = "TrojanSpy:AndroidOS/KevDroid.A,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 09 00 00 "
		
	strings :
		$a_00_0 = {2f 43 61 6c 6c 6c 6f 67 2e 74 78 74 } //1 /Calllog.txt
		$a_00_1 = {2f 69 63 6c 6f 75 64 2f 74 6d 70 2d 77 65 62 2e 64 61 74 2d 65 6e 63 } //1 /icloud/tmp-web.dat-enc
		$a_00_2 = {2f 73 64 63 61 72 64 2f 72 65 73 75 6c 74 2d 66 69 6c 65 2e 64 61 74 } //1 /sdcard/result-file.dat
		$a_00_3 = {3f 74 79 70 65 3d 63 6f 6d 6d 61 6e 64 26 64 69 72 65 63 74 69 6f 6e 3d 72 65 63 65 69 76 65 26 69 64 3d } //1 ?type=command&direction=receive&id=
		$a_00_4 = {4d 59 5f 50 45 52 4d 49 53 53 49 4f 4e 53 5f 52 45 51 55 45 53 54 5f 4e 45 45 44 45 44 50 45 52 4d 49 53 53 49 4f 4e 53 } //1 MY_PERMISSIONS_REQUEST_NEEDEDPERMISSIONS
		$a_00_5 = {57 45 42 5f 45 4e 43 5f 50 41 54 48 } //1 WEB_ENC_PATH
		$a_00_6 = {5f 65 78 63 65 70 74 65 64 45 78 74 65 6e 73 69 6f 6e 73 } //1 _exceptedExtensions
		$a_00_7 = {67 65 74 41 6c 6c 53 4d 53 4a 53 4f 4e } //1 getAllSMSJSON
		$a_00_8 = {70 72 6f 63 65 73 73 49 6d 70 6f 72 74 61 6e 74 46 69 6c 65 } //1 processImportantFile
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1) >=7
 
}