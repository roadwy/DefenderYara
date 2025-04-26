
rule TrojanDownloader_O97M_Valak_PB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Valak.PB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {3d 20 45 6e 76 69 72 6f 6e 28 22 74 65 6d 70 22 29 20 26 20 22 5c 6d 61 69 6e 2e 74 68 65 6d 65 22 } //1 = Environ("temp") & "\main.theme"
		$a_00_1 = {3d 20 41 63 74 69 76 65 57 69 6e 64 6f 77 2e 53 70 6c 69 74 } //1 = ActiveWindow.Split
		$a_00_2 = {64 39 63 63 34 32 65 30 2e 53 65 6e 64 } //1 d9cc42e0.Send
		$a_00_3 = {43 61 6c 6c 20 65 64 33 39 33 31 61 62 2e 65 78 65 63 28 66 32 36 65 33 39 66 65 29 } //1 Call ed3931ab.exec(f26e39fe)
		$a_00_4 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 } //1 CreateObject("wscript.shell")
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}