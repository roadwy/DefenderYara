
rule TrojanDownloader_O97M_Obfuse_RVL_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RVL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {6f 62 6a 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 } //1 obj = CreateObject("wscript.shell")
		$a_02_1 = {33 39 2e 31 30 30 2e 31 35 39 2e 38 2f 61 61 61 22 20 2b 20 52 75 6e 52 65 73 75 6c 74 20 2b 20 52 75 6e 52 65 73 75 6c 74 77 68 6f 61 6d 69 90 0a 3d 00 55 52 4c 20 3d 20 22 68 74 74 70 3a 2f 2f } //1
		$a_00_2 = {6f 62 6a 48 54 54 50 2e 4f 70 65 6e 20 22 50 4f 53 54 22 2c 20 55 52 4c 2c 20 46 61 6c 73 65 } //1 objHTTP.Open "POST", URL, False
		$a_00_3 = {65 78 65 52 73 20 3d 20 6f 62 6a 2e 45 78 65 63 28 22 77 68 6f 61 6d 69 22 29 } //1 exeRs = obj.Exec("whoami")
		$a_00_4 = {6f 62 6a 2e 45 78 65 63 28 22 69 70 63 6f 6e 66 69 67 20 22 29 } //1 obj.Exec("ipconfig ")
		$a_00_5 = {65 78 65 52 73 2e 53 74 64 4f 75 74 2e 52 65 61 64 41 6c 6c } //1 exeRs.StdOut.ReadAll
		$a_00_6 = {6f 62 6a 48 54 54 50 2e 73 65 6e 64 20 28 22 22 29 } //1 objHTTP.send ("")
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}