
rule TrojanDownloader_O97M_Obfuse_LN_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.LN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_00_0 = {3d 20 22 77 22 20 26 20 52 65 70 6c 61 63 65 28 22 77 73 63 6f 6e 72 6f 6e 69 70 6f 6e 74 6f 6e 20 2f 62 6f 6e 20 2f 6f 6e 65 } //1 = "w" & Replace("wsconroniponton /bon /one
		$a_00_1 = {3d 20 22 63 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 22 20 26 20 45 6d 70 74 79 20 26 20 22 5c 44 6f 63 75 6d 65 6e 74 73 5c 22 20 26 20 22 69 6e 66 6f 2e 74 78 74 22 20 26 20 45 6d 70 74 79 } //1 = "c:\Users\Public" & Empty & "\Documents\" & "info.txt" & Empty
		$a_00_2 = {53 75 62 20 4d 61 6b 65 57 65 62 51 75 65 72 79 28 29 } //1 Sub MakeWebQuery()
		$a_00_3 = {6c 6c 20 3d 20 22 68 74 74 22 } //1 ll = "htt"
		$a_00_4 = {6c 6c 20 3d 20 6c 6c 20 26 20 22 70 73 3a 22 } //1 ll = ll & "ps:"
		$a_00_5 = {6c 6c 20 3d 20 6c 6c 20 26 20 22 2f 2f 73 68 65 72 70 61 22 } //1 ll = ll & "//sherpa"
		$a_00_6 = {6c 6c 20 3d 20 6c 6c 20 26 20 22 2e 63 61 73 61 2f 77 70 2d 22 20 26 20 45 6d 70 74 79 20 26 20 45 6d 70 74 79 20 26 20 22 22 20 26 20 22 69 6e 66 6f 2e 70 22 } //1 ll = ll & ".casa/wp-" & Empty & Empty & "" & "info.p"
		$a_00_7 = {6c 6c 20 3d 20 6c 6c 20 26 20 22 68 70 22 } //1 ll = ll & "hp"
		$a_00_8 = {53 65 74 20 73 68 46 69 72 73 74 51 74 72 } //1 Set shFirstQtr
		$a_00_9 = {55 52 4c 3b 22 20 26 20 6c 6c 2c 20 44 65 73 74 69 6e 61 74 69 6f 6e 3a 3d 20 5f } //1 URL;" & ll, Destination:= _
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1) >=10
 
}