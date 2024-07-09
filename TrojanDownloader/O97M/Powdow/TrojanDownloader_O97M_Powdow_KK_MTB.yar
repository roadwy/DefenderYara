
rule TrojanDownloader_O97M_Powdow_KK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.KK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 63 3a 5c 77 69 6e 64 6f 77 73 5c 65 78 70 6c 6f 72 65 72 2e 65 78 65 20 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 6c 69 73 74 62 6f 78 50 61 73 74 65 43 6f 75 6e 74 65 72 2e 68 74 61 22 } //1 = "c:\windows\explorer.exe c:\programdata\listboxPasteCounter.hta"
		$a_01_1 = {6d 65 6d 49 6e 64 65 78 2e 65 78 65 63 20 70 28 72 6d 29 } //1 memIndex.exec p(rm)
		$a_01_2 = {3d 20 53 70 6c 69 74 28 70 28 66 72 6d 2e 72 6d 29 2c 20 22 20 22 29 } //1 = Split(p(frm.rm), " ")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Powdow_KK_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.KK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 63 3a 5c 77 69 6e 64 6f 77 73 5c 65 78 70 6c 6f 72 65 72 2e 65 78 65 20 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 73 63 72 65 65 6e 4f 70 74 69 6f 6e 54 65 78 74 62 6f 78 2e 68 74 61 22 } //1 = "c:\windows\explorer.exe c:\programdata\screenOptionTextbox.hta"
		$a_01_1 = {76 61 72 4c 6f 61 64 41 72 72 61 79 2e 65 78 65 63 20 70 28 72 6d 29 } //1 varLoadArray.exec p(rm)
		$a_01_2 = {3d 20 53 70 6c 69 74 28 70 28 66 72 6d 2e 72 6d 29 2c 20 22 20 22 29 } //1 = Split(p(frm.rm), " ")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Powdow_KK_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Powdow.KK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 22 20 26 20 73 68 65 20 26 20 22 6c 22 29 2e 65 78 65 63 28 70 73 6f 77 65 72 73 73 20 26 20 22 68 65 6c 6c 20 2d 77 20 48 69 64 64 65 6e 20 49 6e 76 6f 6b 65 2d 57 65 62 52 65 71 75 65 73 74 20 2d 55 72 69 } //1 .CreateObject("wscript." & she & "l").exec(psowerss & "hell -w Hidden Invoke-WebRequest -Uri
		$a_01_1 = {68 74 74 70 3a 2f 2f 6c 61 6e 64 69 6e 67 2e 79 65 74 69 61 70 70 2e 65 63 2f 49 44 78 36 2f 46 4c 50 5f 35 30 31 32 5f 33 30 36 5f 31 37 31 2e 65 78 } //1 http://landing.yetiapp.ec/IDx6/FLP_5012_306_171.ex
		$a_01_2 = {26 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 63 68 65 63 6b 67 69 72 6c 2e 65 78 22 } //1 & "C:\Users\Public\Documents\checkgirl.ex"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Powdow_KK_MTB_4{
	meta:
		description = "TrojanDownloader:O97M/Powdow.KK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 22 20 26 20 73 68 65 29 2e 65 78 65 63 28 [0-0d] 20 26 20 [0-0d] 20 26 20 22 20 2d 77 20 22 20 26 20 73 65 61 73 65 20 26 20 22 20 49 6e 76 6f 6b 65 2d 57 65 62 52 65 71 75 65 73 74 20 2d 55 72 69 } //1
		$a_01_1 = {68 74 74 70 3a 2f 2f 61 66 6d 73 2e 6f 72 67 2e 75 6b 2f 6a 73 2f 6d 65 67 61 2e 65 78 } //1 http://afms.org.uk/js/mega.ex
		$a_03_2 = {2d 4f 75 74 46 22 20 26 20 22 69 6c 65 20 22 20 26 20 43 68 72 28 33 34 29 20 26 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c [0-0f] 2e 65 78 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Powdow_KK_MTB_5{
	meta:
		description = "TrojanDownloader:O97M/Powdow.KK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 22 20 26 20 73 68 65 20 26 20 22 6c 22 29 2e 65 78 65 63 28 70 73 6f 77 65 72 73 73 20 26 20 22 68 65 6c 6c 20 2d 77 20 22 20 26 20 73 65 61 73 65 20 26 20 22 6e 20 49 6e 76 6f 6b 65 2d 57 65 62 52 65 71 75 65 73 74 20 2d 55 72 69 } //1 .CreateObject("wscript." & she & "l").exec(psowerss & "hell -w " & sease & "n Invoke-WebRequest -Uri
		$a_01_1 = {68 74 74 70 3a 2f 2f 73 63 61 6c 61 64 65 76 65 6c 6f 70 6d 65 6e 74 73 2e 73 63 61 6c 61 64 65 76 63 6f 2e 63 6f 6d 2f 31 33 5a 2f 49 4d 47 5f 30 30 31 32 36 33 30 38 32 2e 65 78 } //1 http://scaladevelopments.scaladevco.com/13Z/IMG_001263082.ex
		$a_01_2 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 74 65 63 68 6e 6f 6c 6f 67 79 70 75 72 70 6f 73 65 2e 65 78 22 } //1 C:\Users\Public\Documents\technologypurpose.ex"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}