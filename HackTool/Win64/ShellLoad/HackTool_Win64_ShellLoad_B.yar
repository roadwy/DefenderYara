
rule HackTool_Win64_ShellLoad_B{
	meta:
		description = "HackTool:Win64/ShellLoad.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 63 6f 64 65 4c 6f 61 64 65 72 } //1 ShellcodeLoader
		$a_01_1 = {73 74 61 67 65 5f 32 5f 73 68 63 5f 78 } //1 stage_2_shc_x
		$a_01_2 = {73 74 61 67 65 5f 31 5f 64 6f 74 6e 65 74 34 30 } //1 stage_1_dotnet40
		$a_01_3 = {31 30 46 31 46 46 39 37 38 36 41 38 39 31 35 38 37 35 35 33 46 30 37 45 34 44 38 34 35 45 35 42 42 42 37 36 31 46 39 44 46 32 45 45 30 44 35 42 34 37 32 35 33 42 36 37 43 42 33 45 43 44 38 46 } //1 10F1FF9786A891587553F07E4D845E5BBB761F9DF2EE0D5B47253B67CB3ECD8F
		$a_01_4 = {31 31 44 32 41 35 42 36 41 34 42 42 44 38 38 30 46 45 39 43 43 41 36 38 41 41 35 42 44 34 39 41 41 39 44 44 31 43 39 45 43 32 38 37 46 31 37 41 42 34 43 41 43 34 43 34 35 37 31 32 41 46 42 46 } //1 11D2A5B6A4BBD880FE9CCA68AA5BD49AA9DD1C9EC287F17AB4CAC4C45712AFBF
		$a_01_5 = {48 69 64 65 48 48 } //1 HideHH
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}