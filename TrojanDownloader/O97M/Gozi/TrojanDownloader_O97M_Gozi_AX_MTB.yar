
rule TrojanDownloader_O97M_Gozi_AX_MTB{
	meta:
		description = "TrojanDownloader:O97M/Gozi.AX!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_03_0 = {3d 20 22 43 3a 5c 75 73 65 72 73 5c 50 75 62 6c 69 63 5c 90 02 05 2e 70 6e 67 22 90 00 } //1
		$a_00_1 = {3d 20 22 68 74 74 70 22 } //1 = "http"
		$a_00_2 = {2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 55 73 65 72 46 6f 72 6d 31 2e } //1 .Open "GET", UserForm1.
		$a_00_3 = {52 65 66 65 72 65 6e 63 65 50 74 72 2e 4f 70 65 6e } //1 ReferencePtr.Open
		$a_00_4 = {53 68 65 6c 6c 40 20 28 57 69 6e 64 6f 77 43 6c 61 73 73 20 2b 20 22 33 32 20 22 20 26 } //1 Shell@ (WindowClass + "32 " &
		$a_03_5 = {28 22 3a 2f 2f 6c 69 6e 65 73 74 61 74 73 2e 63 61 73 61 2f 90 02 0a 2e 6a 70 67 22 29 90 00 } //1
		$a_00_6 = {42 75 66 66 65 72 43 6f 6e 73 74 2e 53 65 6e 64 } //1 BufferConst.Send
		$a_00_7 = {52 65 66 65 72 65 6e 63 65 50 74 72 2e 57 72 69 74 65 20 42 75 66 66 65 72 43 6f 6e 73 74 2e 52 65 73 70 6f 6e 73 65 42 6f 64 79 } //1 ReferencePtr.Write BufferConst.ResponseBody
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_03_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=8
 
}