
rule TrojanDownloader_O97M_Obfuse_JJ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2e 6a 73 22 } //1 .js"
		$a_01_1 = {3d 20 45 6e 76 69 72 6f 6e 28 22 77 69 6e 64 69 72 22 29 20 2b 20 22 5c 54 65 6d 70 22 } //1 = Environ("windir") + "\Temp"
		$a_03_2 = {4f 70 65 6e 20 [0-15] 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 } //1
		$a_01_3 = {2e 43 61 70 74 69 6f 6e } //1 .Caption
		$a_01_4 = {22 53 68 65 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 } //1 "Shell.Application"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Obfuse_JJ_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {41 73 20 53 74 72 69 6e 67 20 3d 20 22 70 2c 3a 2c 5c 2c 6a 2c 76 2c 61 2c 71 2c 62 2c 6a 2c 66 2c 5c 2c 66 2c 6c 2c 66 2c 67 2c 72 2c 7a 2c 33 2c 32 2c 5c 2c 7a 2c 66 2c 75 2c 67 2c 6e 2c 2e 2c 72 2c 6b 2c 72 2c } //1 As String = "p,:,\,j,v,a,q,b,j,f,\,f,l,f,g,r,z,3,2,\,z,f,u,g,n,.,r,k,r,
		$a_01_1 = {41 73 20 53 74 72 69 6e 67 20 3d 20 22 50 2c 3a 2c 5c 2c 68 2c 66 2c 72 2c 65 2c 66 2c 5c 2c 63 2c 68 2c 6f 2c 79 2c 76 2c 70 2c 5c 2c 76 2c 61 2c 2e 2c 70 2c 62 2c 7a 2c } //1 As String = "P,:,\,h,f,r,e,f,\,c,h,o,y,v,p,\,v,a,.,p,b,z,
		$a_01_2 = {41 73 20 53 74 72 69 6e 67 20 3d 20 22 50 2c 3a 2c 5c 2c 68 2c 66 2c 72 2c 65 2c 66 2c 5c 2c 63 2c 68 2c 6f 2c 79 2c 76 2c 70 2c 5c 2c 76 2c 61 2c 2e 2c 75 2c 67 2c 7a 2c 79 2c } //1 As String = "P,:,\,h,f,r,e,f,\,c,h,o,y,v,p,\,v,a,.,u,g,z,y,
		$a_03_3 = {52 65 70 6c 61 63 65 28 [0-0a] 2c 20 [0-0a] 2c 20 22 22 29 } //1
		$a_01_4 = {66 72 6d 2e 74 78 74 2e 74 65 78 74 } //1 frm.txt.text
		$a_01_5 = {50 72 69 6e 74 20 23 46 69 6c 65 4e 75 6d 62 65 72 2c 20 53 70 63 } //1 Print #FileNumber, Spc
		$a_03_6 = {4d 69 64 24 28 [0-0a] 2c 20 [0-0a] 2c 20 31 29 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_03_6  & 1)*1) >=7
 
}
rule TrojanDownloader_O97M_Obfuse_JJ_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {41 73 20 53 74 72 69 6e 67 20 3d 20 22 63 26 3a 26 5c 26 77 26 69 26 6e 26 64 26 6f 26 77 26 73 26 5c 26 73 26 79 26 73 26 74 26 65 26 6d 26 33 26 32 26 5c 26 6d 26 73 26 68 26 74 26 61 26 2e 26 65 26 78 26 65 26 } //1 As String = "c&:&\&w&i&n&d&o&w&s&\&s&y&s&t&e&m&3&2&\&m&s&h&t&a&.&e&x&e&
		$a_01_1 = {41 73 20 53 74 72 69 6e 67 20 3d 20 22 43 26 3a 26 5c 26 75 26 73 26 65 26 72 26 73 26 5c 26 70 26 75 26 62 26 6c 26 69 26 63 26 5c 26 63 26 61 26 6c 26 63 26 2e 26 63 26 6f 26 6d 26 } //1 As String = "C&:&\&u&s&e&r&s&\&p&u&b&l&i&c&\&c&a&l&c&.&c&o&m&
		$a_01_2 = {41 73 20 53 74 72 69 6e 67 20 3d 20 22 43 26 3a 26 5c 26 75 26 73 26 65 26 72 26 73 26 5c 26 70 26 75 26 62 26 6c 26 69 26 63 26 5c 26 69 26 6e 26 2e 26 68 26 74 26 6d 26 6c 26 } //1 As String = "C&:&\&u&s&e&r&s&\&p&u&b&l&i&c&\&i&n&.&h&t&m&l&
		$a_03_3 = {52 65 70 6c 61 63 65 28 [0-0a] 2c 20 [0-0a] 2c 20 22 22 29 } //1
		$a_01_4 = {66 72 6d 2e 74 78 74 2e 74 65 78 74 } //1 frm.txt.text
		$a_01_5 = {50 72 69 6e 74 20 23 46 69 6c 65 4e 75 6d 62 65 72 2c 20 53 70 63 } //1 Print #FileNumber, Spc
		$a_03_6 = {41 73 63 28 4d 69 64 24 28 [0-0a] 2c 20 [0-0a] 2c 20 31 29 29 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_03_6  & 1)*1) >=7
 
}
rule TrojanDownloader_O97M_Obfuse_JJ_MTB_4{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {41 73 20 53 74 72 69 6e 67 20 3d 20 22 70 2c 3a 2c 5c 2c 6a 2c 76 2c 61 2c 71 2c 62 2c 6a 2c 66 2c 5c 2c 66 2c 6c 2c 66 2c 67 2c 72 2c 7a 2c 33 2c 32 2c 5c 2c 7a 2c 66 2c 75 2c 67 2c 6e 2c 2e 2c 72 2c 6b 2c 72 2c } //1 As String = "p,:,\,j,v,a,q,b,j,f,\,f,l,f,g,r,z,3,2,\,z,f,u,g,n,.,r,k,r,
		$a_01_1 = {41 73 20 53 74 72 69 6e 67 20 3d 20 22 50 2c 3a 2c 5c 2c 68 2c 66 2c 72 2c 65 2c 66 2c 5c 2c 63 2c 68 2c 6f 2c 79 2c 76 2c 70 2c 5c 2c 76 2c 61 2c 2e 2c 70 2c 62 2c 7a 2c } //1 As String = "P,:,\,h,f,r,e,f,\,c,h,o,y,v,p,\,v,a,.,p,b,z,
		$a_01_2 = {41 73 20 53 74 72 69 6e 67 20 3d 20 22 50 2c 3a 2c 5c 2c 68 2c 66 2c 72 2c 65 2c 66 2c 5c 2c 63 2c 68 2c 6f 2c 79 2c 76 2c 70 2c 5c 2c 76 2c 61 2c 2e 2c 75 2c 67 2c 7a 2c 79 2c } //1 As String = "P,:,\,h,f,r,e,f,\,c,h,o,y,v,p,\,v,a,.,u,g,z,y,
		$a_03_3 = {52 65 70 6c 61 63 65 28 [0-0a] 2c 20 [0-0a] 2c 20 22 22 29 } //1
		$a_01_4 = {66 72 6d 2e 74 78 74 2e 74 65 78 74 } //1 frm.txt.text
		$a_01_5 = {50 72 69 6e 74 20 23 46 69 6c 65 4e 75 6d 62 65 72 2c 20 53 70 63 } //1 Print #FileNumber, Spc
		$a_03_6 = {4c 6f 6f 70 20 57 68 69 6c 65 20 [0-0a] 20 3e 20 28 [0-0a] 20 2d 20 31 29 } //1
		$a_03_7 = {41 73 63 28 4d 69 64 28 [0-0a] 2c 20 [0-0a] 2c 20 31 29 29 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_03_6  & 1)*1+(#a_03_7  & 1)*1) >=8
 
}