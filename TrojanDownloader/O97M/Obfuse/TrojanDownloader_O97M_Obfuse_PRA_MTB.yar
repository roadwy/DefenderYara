
rule TrojanDownloader_O97M_Obfuse_PRA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PRA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {70 50 74 68 20 3d 20 43 75 72 44 69 72 20 26 20 22 5c 6b 6e 6c 61 2e 64 61 74 22 } //1 pPth = CurDir & "\knla.dat"
		$a_01_1 = {53 65 74 20 77 73 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 22 20 26 20 22 63 72 69 70 22 20 26 20 22 74 2e 53 68 22 20 26 20 22 65 6c 6c 22 29 } //1 Set ws = CreateObject("WS" & "crip" & "t.Sh" & "ell")
		$a_01_2 = {53 65 74 20 77 70 65 20 3d 20 77 73 2e 45 6e 76 69 72 6f 6e 6d 65 6e 74 28 22 50 72 6f 22 20 26 20 22 63 65 22 20 26 20 22 73 73 22 29 } //1 Set wpe = ws.Environment("Pro" & "ce" & "ss")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}