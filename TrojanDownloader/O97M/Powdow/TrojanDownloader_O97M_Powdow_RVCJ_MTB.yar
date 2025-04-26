
rule TrojanDownloader_O97M_Powdow_RVCJ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVCJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 73 68 65 6c 6c 65 78 65 63 75 74 65 62 6d 76 6b 64 6c 66 64 6a 6b 6c 66 61 73 66 77 2c 70 65 6f 73 6b 61 77 65 66 67 65 61 2c 22 22 2c 22 6f 70 65 6e 22 2c 30 65 6e 64 73 75 62 } //1 .shellexecutebmvkdlfdjklfasfw,peoskawefgea,"","open",0endsub
		$a_01_1 = {3d 72 65 70 6c 61 63 65 28 6f 65 69 6f 69 77 61 6f 66 73 6f 64 61 66 2c 70 77 6f 65 6b 64 73 66 77 2c 22 22 29 } //1 =replace(oeioiwaofsodaf,pwoekdsfw,"")
		$a_01_2 = {64 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 73 65 74 69 65 6f 61 6c 73 64 66 61 73 66 65 66 61 66 61 77 65 3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 73 68 65 6c 6c 2e 61 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //1 document_open()setieoalsdfasfefafawe=createobject("shell.application")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Powdow_RVCJ_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVCJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0b 00 0b 00 05 00 00 "
		
	strings :
		$a_01_0 = {61 68 72 30 63 64 6f 76 6c 7a 71 31 6c 6a 67 30 6c 6a 61 75 6d 74 63 7a 6c 32 72 76 64 32 35 73 62 32 66 6b 78 7a 69 79 6c 33 6e 6c 63 6e 7a 6c 63 69 35 6c 65 67 75 } //1 ahr0cdovlzq1ljg0ljaumtczl2rvd25sb2fkxziyl3nlcnzlci5legu
		$a_01_1 = {61 68 72 30 63 64 6f 76 6c 7a 65 34 6e 73 34 78 6e 74 79 75 6e 7a 69 75 6e 7a 67 76 6d 69 35 6c 65 67 75 6e 6f 79 61 6b 75 68 72 } //1 ahr0cdovlze4ns4xntyunziunzgvmi5legunoyakuhr
		$a_01_2 = {61 68 72 30 63 64 6f 76 6c 7a 6b 30 6c 6a 69 7a 6d 69 34 79 6e 64 6b 75 6d 74 79 78 6c 33 76 77 7a 67 66 30 79 73 39 7a 64 6d 6d 78 6c 6d 76 34 7a 73 } //1 ahr0cdovlzk0ljizmi4yndkumtyxl3vwzgf0ys9zdmmxlmv4zs
		$a_01_3 = {70 6f 77 65 72 73 68 65 6c 6c 2d 65 24 63 3b 22 70 72 6f 67 72 61 6d 3d 73 68 65 6c 6c 28 63 6d 64 73 74 72 2c 76 62 68 69 64 65 29 61 70 70 6c 69 63 61 74 69 6f 6e 2e 73 63 72 65 65 6e 75 70 64 61 74 69 6e 67 3d 74 72 75 65 65 6e 64 73 75 62 } //5 powershell-e$c;"program=shell(cmdstr,vbhide)application.screenupdating=trueendsub
		$a_01_4 = {61 75 74 6f 6f 70 65 6e 28 29 } //5 autoopen()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5) >=11
 
}