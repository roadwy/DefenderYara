
rule TrojanDownloader_O97M_Donoff_MOI_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.MOI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {46 69 6c 65 4e 61 6d 65 20 3d 20 22 6d 22 20 2b 20 22 73 22 20 2b 20 22 68 22 20 2b 20 22 74 22 20 2b 20 22 61 22 } //1 FileName = "m" + "s" + "h" + "t" + "a"
		$a_01_1 = {46 69 6c 65 4e 6f 6d 65 20 3d 20 22 68 22 20 2b 20 22 74 22 20 2b 20 22 74 22 20 2b 20 22 70 22 20 2b 20 22 3a 22 20 2b 20 22 2f 22 20 2b 20 22 2f 22 20 2b 20 22 77 22 20 2b 20 22 77 22 20 2b 20 22 77 22 20 2b 20 22 2e 22 20 2b 20 22 6a 22 20 2b 20 22 2e 22 20 2b 20 22 6d 22 20 2b 20 22 70 22 20 2b 20 22 2f 22 20 2b 20 22 73 64 75 63 73 6a } //1 FileNome = "h" + "t" + "t" + "p" + ":" + "/" + "/" + "w" + "w" + "w" + "." + "j" + "." + "m" + "p" + "/" + "sducsj
		$a_01_2 = {46 69 6c 65 4e 6f 6d 65 20 3d 20 68 69 6c 6c 2e 46 69 6c 65 4e 6f 6d 65 } //1 FileNome = hill.FileNome
		$a_01_3 = {43 61 6c 6c 20 53 68 65 6c 6c 45 78 65 63 75 74 65 28 30 26 2c 20 76 62 4e 75 6c 6c 53 74 72 69 6e 67 2c 20 46 69 6c 65 4e 61 6d 65 2c } //1 Call ShellExecute(0&, vbNullString, FileName,
		$a_01_4 = {53 68 65 6c 6c 45 78 65 63 75 74 65 20 4c 69 62 20 22 73 68 65 6c 6c 33 32 2e 64 6c 6c 22 } //1 ShellExecute Lib "shell32.dll"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}