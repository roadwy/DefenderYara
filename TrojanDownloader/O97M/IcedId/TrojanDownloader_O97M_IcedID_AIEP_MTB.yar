
rule TrojanDownloader_O97M_IcedID_AIEP_MTB{
	meta:
		description = "TrojanDownloader:O97M/IcedID.AIEP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {2e 65 78 65 63 20 70 28 74 65 78 74 62 6f 78 56 69 65 77 29 20 26 20 22 20 22 20 26 20 70 28 70 61 73 74 65 49 74 65 72 61 74 6f 72 29 } //1 .exec p(textboxView) & " " & p(pasteIterator)
		$a_01_1 = {50 75 62 6c 69 63 20 53 75 62 20 62 75 74 74 6f 6e 31 5f 43 6c 69 63 6b 28 29 } //1 Public Sub button1_Click()
		$a_01_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 } //1 = CreateObject("wscript.shell")
		$a_01_3 = {3d 20 22 22 20 26 20 71 75 65 72 79 4d 61 69 6e 20 26 20 22 22 } //1 = "" & queryMain & ""
		$a_01_4 = {3d 20 70 28 66 72 6d 2e 62 75 74 74 6f 6e 31 2e 43 61 70 74 69 6f 6e 29 } //1 = p(frm.button1.Caption)
		$a_03_5 = {66 72 6d 2e 62 75 74 74 6f 6e 31 5f 43 6c 69 63 6b 90 0c 02 00 45 6e 64 20 53 75 62 } //1
		$a_01_6 = {3c 68 74 6d 6c 3e 3c 62 6f 64 79 3e 3c 64 69 76 20 69 64 3d 27 63 6f 6e 74 65 6e 74 27 3e 66 54 74 6c } //1 <html><body><div id='content'>fTtl
		$a_01_7 = {54 69 6d 65 6f 75 74 20 3d 20 36 30 30 } //1 Timeout = 600
		$a_03_8 = {3d 20 2e 54 61 67 90 0c 02 00 45 6e 64 20 57 69 74 68 90 0c 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e } //1
		$a_03_9 = {3d 20 2e 43 61 70 74 69 6f 6e 90 0c 02 00 45 6e 64 20 57 69 74 68 90 0c 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_03_8  & 1)*1+(#a_03_9  & 1)*1) >=10
 
}