
rule Trojan_BAT_Tasker_NB_MTB{
	meta:
		description = "Trojan:BAT/Tasker.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_03_0 = {00 06 11 04 06 11 04 91 ?? ?? ?? 00 00 59 d2 9c 00 11 04 17 58 13 04 } //3
		$a_81_1 = {68 74 74 70 73 3a 2f 2f 6f 6e 65 64 72 69 76 65 2e 6c 69 76 65 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 3f 72 65 73 69 64 3d 35 39 32 36 31 43 37 45 34 31 42 36 34 37 38 41 25 32 31 32 32 33 26 61 75 74 68 6b 65 79 3d 21 41 45 4a 5a 57 37 47 74 52 58 45 66 4f 47 63 } //1 https://onedrive.live.com/download?resid=59261C7E41B6478A%21223&authkey=!AEJZW7GtRXEfOGc
		$a_81_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_81_3 = {53 79 73 74 65 6d 2e 52 65 66 6c 65 63 74 69 6f 6e 2e 41 73 73 65 6d 62 6c 79 } //1 System.Reflection.Assembly
		$a_81_4 = {49 6e 76 6f 6b 65 } //1 Invoke
	condition:
		((#a_03_0  & 1)*3+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=7
 
}