
rule TrojanDownloader_O97M_Donoff_MXM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.MXM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {70 73 6f 77 65 72 73 73 20 3d 20 22 70 6f 77 65 72 73 22 } //1 psowerss = "powers"
		$a_01_1 = {73 68 65 20 3d 20 22 73 68 65 6c 22 } //1 she = "shel"
		$a_01_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4f 75 74 6c 6f 6f 6b 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //1 CreateObject("Outlook.Application")
		$a_01_3 = {73 65 61 73 65 20 3d 20 22 48 69 64 64 65 22 } //1 sease = "Hidde"
		$a_01_4 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 22 20 26 20 73 68 65 20 26 20 22 6c 22 29 2e } //1 CreateObject("wscript." & she & "l").
		$a_01_5 = {65 78 65 63 28 70 73 6f 77 65 72 73 73 20 26 20 22 68 65 6c 6c 20 2d 77 20 22 20 26 20 73 65 61 73 65 20 26 20 22 6e 20 49 6e 76 6f 6b 65 2d 57 65 62 52 65 71 75 65 73 74 20 2d 55 72 69 20 22 20 26 } //1 exec(psowerss & "hell -w " & sease & "n Invoke-WebRequest -Uri " &
		$a_03_6 = {43 68 72 28 33 34 29 20 26 20 22 68 74 74 70 3a 2f 2f 73 63 61 6c 61 64 65 76 65 6c 6f 70 6d 65 6e 74 73 2e 73 63 61 6c 61 64 65 76 63 6f 2e 63 6f 6d 2f [0-11] 2e 65 78 22 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_03_6  & 1)*1) >=7
 
}