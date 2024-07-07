
rule Virus_O97M_Selaieproc_gen_A{
	meta:
		description = "Virus:O97M/Selaieproc.gen!A,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {53 68 65 6c 6c 20 22 43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 49 45 58 50 4c 4f 52 45 2e 45 58 45 20 22 } //1 Shell "C:\Program Files\Internet Explorer\IEXPLORE.EXE "
		$a_02_1 = {43 6f 64 65 4d 6f 64 75 6c 65 2e 49 6e 73 65 72 74 4c 69 6e 65 73 20 90 02 04 2c 20 22 53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 90 00 } //1
		$a_00_2 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 74 61 72 74 75 70 50 61 74 68 } //1 Application.StartupPath
		$a_00_3 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 65 6e 64 4b 65 79 73 20 22 25 28 71 74 6d 73 74 76 29 7b 45 4e 54 45 52 7d 22 } //1 Application.SendKeys "%(qtmstv){ENTER}"
		$a_00_4 = {2e 69 6e 73 74 61 6e 63 65 73 6f 66 28 22 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 22 29 } //1 .instancesof("Win32_Process")
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}