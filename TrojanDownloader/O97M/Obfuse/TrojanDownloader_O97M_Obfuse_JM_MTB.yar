
rule TrojanDownloader_O97M_Obfuse_JM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {53 68 65 6c 6c 20 22 22 22 22 20 2b 20 22 22 20 2b 20 22 6d 73 22 20 2b 20 22 68 74 61 22 22 22 22 22 20 2b 20 22 68 74 74 70 73 22 20 2b 20 22 3a 5c 5c [0-14] 40 6a 2e 6d 70 5c [0-18] 22 22 22 } //3
		$a_01_1 = {53 75 62 20 41 75 74 6f 5f 4f 70 65 6e 28 29 } //1 Sub Auto_Open()
		$a_01_2 = {53 75 62 20 63 61 6c 63 75 6c 61 74 6f 72 28 29 } //1 Sub calculator()
		$a_01_3 = {53 75 62 20 41 75 74 6f 5f 43 6c 6f 73 65 28 29 } //1 Sub Auto_Close()
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Obfuse_JM_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {4f 70 65 6e 28 22 47 45 54 22 2c 20 [0-0a] 2c 20 46 61 6c 73 65 29 } //1
		$a_03_1 = {4d 69 64 28 [0-0a] 2c 20 [0-0a] 2c 20 31 29 } //1
		$a_03_2 = {53 74 72 43 6f 6e 76 28 [0-0a] 2c 20 36 34 29 } //1
		$a_03_3 = {65 78 65 63 28 [0-0a] 20 26 20 22 20 22 20 26 20 [0-0a] 29 } //1
		$a_03_4 = {45 6e 76 69 72 6f 6e 28 22 74 6d 70 22 29 20 26 20 22 5c [0-0a] 2e 6a 70 67 22 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Obfuse_JM_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c [0-08] 2e 22 20 26 } //1
		$a_03_1 = {53 74 72 43 6f 6e 76 28 [0-08] 2c 20 76 62 55 6e 69 63 6f 64 65 } //1
		$a_03_2 = {53 70 6c 69 74 28 [0-08] 2c 20 22 31 32 33 34 35 36 37 38 22 29 } //1
		$a_03_3 = {2e 65 78 65 63 20 28 [0-08] 29 } //1
		$a_01_4 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 } //1 CreateObject("wscript.shell")
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Obfuse_JM_MTB_4{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c [0-08] 2e 22 20 26 } //1
		$a_03_1 = {53 74 72 43 6f 6e 76 28 [0-08] 2c 20 76 62 55 6e 69 63 6f 64 65 } //1
		$a_03_2 = {53 70 6c 69 74 28 [0-08] 2c 20 [0-08] 29 } //1
		$a_03_3 = {2e 65 78 65 63 20 28 [0-08] 29 } //1
		$a_03_4 = {41 73 20 53 74 72 69 6e 67 20 3d 20 22 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c [0-0a] 2e 70 64 66 22 29 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Obfuse_JM_MTB_5{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {41 73 20 53 74 72 69 6e 67 20 3d 20 22 63 [0-02] 3a [0-02] 5c [0-02] 70 [0-02] 72 [0-02] 6f [0-02] 67 [0-02] 72 [0-02] 61 [0-02] 6d [0-02] 64 [0-02] 61 [0-02] 74 [0-02] 61 [0-02] 5c [0-0f] 2e [0-02] 6a [0-02] 70 [0-02] 67 [0-02] 22 } //3
		$a_03_1 = {4d 69 64 28 [0-0a] 2c 20 [0-0a] 2c 20 31 29 } //1
		$a_03_2 = {53 74 72 43 6f 6e 76 28 [0-0a] 2c 20 36 34 29 } //1
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Obfuse_JM_MTB_6{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {41 73 20 53 74 72 69 6e 67 20 3d 20 22 63 [0-02] 3a [0-02] 5c [0-02] 70 [0-02] 72 [0-02] 6f [0-02] 67 [0-02] 72 [0-02] 61 [0-02] 6d [0-02] 64 [0-02] 61 [0-02] 74 [0-02] 61 [0-02] 5c [0-0f] 2e [0-02] 6a [0-02] 70 [0-02] 67 [0-02] 22 } //3
		$a_01_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 69 6e 48 74 74 70 2e 57 69 6e 48 74 74 70 52 65 71 75 65 73 74 2e 35 2e 31 22 29 } //1 CreateObject("WinHttp.WinHttpRequest.5.1")
		$a_03_2 = {26 20 4d 69 64 28 [0-0a] 2c 20 [0-0a] 2c 20 31 29 } //1
		$a_03_3 = {53 74 72 43 6f 6e 76 28 [0-0a] 2c 20 36 34 29 } //1
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Obfuse_JM_MTB_7{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {2e 65 78 65 63 20 [0-0a] 20 26 20 22 20 22 20 26 20 [0-0a] 28 22 63 [0-02] 3a [0-02] 5c [0-02] 70 [0-02] 72 [0-02] 6f [0-02] 67 [0-02] 72 [0-02] 61 [0-02] 6d [0-02] 64 [0-02] 61 [0-02] 74 [0-02] 61 [0-02] 5c [0-0f] 2e [0-02] 6a [0-02] 70 [0-02] 67 [0-02] 22 29 } //3
		$a_01_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 69 6e 48 74 74 70 2e 57 69 6e 48 74 74 70 52 65 71 75 65 73 74 2e 35 2e 31 22 29 } //1 CreateObject("WinHttp.WinHttpRequest.5.1")
		$a_03_2 = {26 20 4d 69 64 28 [0-0a] 2c 20 [0-0a] 2c 20 31 29 } //1
		$a_03_3 = {53 74 72 43 6f 6e 76 28 [0-0a] 2c 20 36 34 29 } //1
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Obfuse_JM_MTB_8{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 08 00 00 "
		
	strings :
		$a_03_0 = {63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c [0-08] 2e 22 20 26 } //1
		$a_03_1 = {53 74 72 43 6f 6e 76 28 [0-08] 2c 20 76 62 55 6e 69 63 6f 64 65 } //1
		$a_03_2 = {53 70 6c 69 74 28 [0-08] 2c 20 [0-08] 29 } //1
		$a_03_3 = {2e 65 78 65 63 20 28 [0-08] 29 } //1
		$a_01_4 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 } //1 CreateObject("wscript.shell")
		$a_01_5 = {33 32 20 74 65 73 74 2e 70 64 66 } //1 32 test.pdf
		$a_03_6 = {41 73 20 53 74 72 69 6e 67 20 3d 20 22 [0-0a] 2e 70 64 66 22 29 } //1
		$a_03_7 = {41 73 20 53 74 72 69 6e 67 20 3d 20 22 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c [0-0a] 2e 70 64 66 22 29 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_03_6  & 1)*1+(#a_03_7  & 1)*1) >=6
 
}
rule TrojanDownloader_O97M_Obfuse_JM_MTB_9{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 08 00 00 "
		
	strings :
		$a_03_0 = {72 33 32 20 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c [0-08] 2e 70 64 66 22 } //2
		$a_03_1 = {72 33 32 20 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c [0-08] 2e 74 78 74 22 } //2
		$a_03_2 = {72 33 32 20 63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c [0-08] 2e 74 78 74 22 } //2
		$a_03_3 = {41 73 20 53 74 72 69 6e 67 20 3d 20 22 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c [0-0a] 2e 70 64 66 22 } //2
		$a_03_4 = {41 73 20 53 74 72 69 6e 67 20 3d 20 22 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c [0-0a] 2e 74 78 74 22 } //2
		$a_03_5 = {41 73 20 53 74 72 69 6e 67 20 3d 20 22 63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c [0-0a] 2e 74 78 74 22 } //2
		$a_03_6 = {53 70 6c 69 74 28 [0-08] 2c 20 [0-08] 29 } //1
		$a_03_7 = {2e 65 78 65 63 28 [0-08] 29 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2+(#a_03_3  & 1)*2+(#a_03_4  & 1)*2+(#a_03_5  & 1)*2+(#a_03_6  & 1)*1+(#a_03_7  & 1)*1) >=6
 
}
rule TrojanDownloader_O97M_Obfuse_JM_MTB_10{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 } //1 CreateObject("Scripting.FileSystemObject")
		$a_03_1 = {43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c [0-19] 22 2c 20 54 72 75 65 29 } //1
		$a_03_2 = {57 72 69 74 65 4c 69 6e 65 20 28 22 [0-19] 22 29 } //1
		$a_01_3 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 51 75 69 74 20 53 61 76 65 43 68 61 6e 67 65 73 3a 3d 46 61 6c 73 65 } //1 Application.Quit SaveChanges:=False
		$a_03_4 = {43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 [0-28] 2e 44 65 66 61 75 6c 74 54 61 72 67 65 74 46 72 61 6d 65 2c 20 54 72 75 65 29 } //1
		$a_03_5 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-28] 2e 54 61 67 29 } //1
		$a_03_6 = {45 78 65 63 20 22 65 78 70 6c 6f 72 65 72 2e 65 78 65 20 22 20 26 20 [0-28] 2e 44 65 66 61 75 6c 74 54 61 72 67 65 74 46 72 61 6d 65 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1+(#a_03_6  & 1)*1) >=7
 
}