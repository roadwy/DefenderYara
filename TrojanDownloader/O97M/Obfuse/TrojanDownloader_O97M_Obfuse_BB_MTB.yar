
rule TrojanDownloader_O97M_Obfuse_BB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {7a 7a 7a 7a 68 5f 62 36 34 20 3d 20 7a 7a 7a 7a 68 5f 62 36 34 20 26 } //1 zzzzh_b64 = zzzzh_b64 &
		$a_01_1 = {22 2f 6c 61 73 64 77 65 2f 62 64 61 61 33 38 31 31 2d 62 62 36 63 2d 34 32 63 37 2d 61 65 32 35 2d 30 33 32 39 66 33 61 35 39 63 65 31 22 2c 20 34 33 36 2c 20 7a 7a 7a 7a 68 } //1 "/lasdwe/bdaa3811-bb6c-42c7-ae25-0329f3a59ce1", 436, zzzzh
		$a_01_2 = {44 79 6e 4d 65 6d 63 70 79 20 61 6c 6c 6f 63 2c 20 7a 7a 7a 7a 68 2c 20 68 72 65 61 64 2c 20 68 77 72 69 74 65 } //1 DynMemcpy alloc, zzzzh, hread, hwrite
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Obfuse_BB_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 20 6d 61 69 6e 2e 72 28 22 63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 72 65 64 4c 69 6e 65 53 65 61 2e 68 74 22 29 } //1 = main.r("c:\users\public\redLineSea.ht")
		$a_01_1 = {2e 43 6f 6e 74 65 6e 74 2e 46 69 6e 64 2e 45 78 65 63 75 74 65 20 46 69 6e 64 54 65 78 74 3a 3d 22 25 5f 22 2c 20 52 65 70 6c 61 63 65 57 69 74 68 3a 3d 22 22 2c 20 52 65 70 6c 61 63 65 3a 3d 77 64 52 65 70 6c 61 63 65 41 6c 6c } //1 .Content.Find.Execute FindText:="%_", ReplaceWith:="", Replace:=wdReplaceAll
		$a_01_2 = {2e 72 75 6e 20 6c 69 6e 65 4c 6f 76 65 4c 61 64 79 } //1 .run lineLoveLady
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Obfuse_BB_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 45 78 70 61 6e 64 45 6e 76 69 72 6f 6e 6d 65 6e 74 53 74 72 69 6e 67 73 28 22 25 54 45 4d 50 25 22 29 20 26 20 22 5c 63 79 6d 5f 31 36 30 30 31 33 38 30 34 33 30 42 44 38 34 42 32 34 2e 65 78 65 22 } //1 .ExpandEnvironmentStrings("%TEMP%") & "\cym_16001380430BD84B24.exe"
		$a_01_1 = {42 61 73 65 64 20 3d 20 42 61 73 65 64 20 26 20 68 63 66 66 67 66 61 77 72 65 6e 6d 28 } //1 Based = Based & hcffgfawrenm(
		$a_03_2 = {26 20 43 68 72 24 28 56 61 6c 28 22 26 48 22 20 26 20 4d 69 64 24 28 [0-0f] 2c 20 [0-0f] 2c 20 32 29 29 29 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Obfuse_BB_MTB_4{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {3d 20 43 68 72 24 28 56 61 6c 28 22 26 48 22 20 26 20 4d 69 64 24 28 [0-0c] 2c 20 [0-0c] 2c 20 32 29 29 29 } //1
		$a_01_1 = {3d 20 6b 75 51 57 47 39 4a 6c 28 55 73 65 72 46 6f 72 6d 31 2e 4c 61 62 65 6c 31 2e 43 61 70 74 69 6f 6e 29 } //1 = kuQWG9Jl(UserForm1.Label1.Caption)
		$a_01_2 = {2e 45 6e 76 69 72 6f 6e 6d 65 6e 74 28 22 70 72 6f 63 65 73 73 22 29 2e 49 74 65 6d 28 22 70 61 72 61 6d 31 22 29 20 3d } //1 .Environment("process").Item("param1") =
		$a_01_3 = {2e 72 75 6e 20 22 63 6d 64 20 2f 63 20 63 61 6c 6c 20 25 70 61 72 61 6d 31 25 22 2c 20 32 } //1 .run "cmd /c call %param1%", 2
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Obfuse_BB_MTB_5{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 53 70 6c 69 74 28 61 66 74 65 72 42 6f 6f 6c 2c 20 22 23 22 29 } //1 = Split(afterBool, "#")
		$a_01_1 = {63 3a 5c 5c 75 73 65 72 73 5c 5c 70 75 62 6c 69 63 5c 5c 6e 61 6d 65 54 70 6c 2e 68 } //1 c:\\users\\public\\nameTpl.h
		$a_01_2 = {4f 70 74 69 6f 6e 61 6c 20 72 65 66 43 6e 74 20 3d 20 22 74 22 2c 20 4f 70 74 69 6f 6e 61 6c 20 6c 42 44 6f 63 75 6d 65 6e 74 20 3d 20 22 61 22 29 } //1 Optional refCnt = "t", Optional lBDocument = "a")
		$a_01_3 = {3d 20 72 65 73 70 6f 6e 73 65 44 65 6c 65 74 65 52 65 73 70 6f 6e 73 65 20 26 20 63 6f 6e 76 65 72 74 53 63 72 20 26 20 22 22 20 26 20 72 65 66 43 6e 74 20 26 20 6c 42 44 6f 63 75 6d 65 6e 74 } //1 = responseDeleteResponse & convertScr & "" & refCnt & lBDocument
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}