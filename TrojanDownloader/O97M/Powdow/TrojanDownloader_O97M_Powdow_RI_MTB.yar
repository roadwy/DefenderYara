
rule TrojanDownloader_O97M_Powdow_RI_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {73 74 72 20 3d 20 73 74 72 20 2b } //1 str = str +
		$a_00_1 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 4e 6f 50 20 2d 4e 6f 6e 49 20 2d 57 20 48 69 64 64 65 6e 20 2d 43 6f 6d 6d 61 6e 64 20 22 22 49 6e 76 6f 6b 65 2d 22 } //1 powershell.exe -NoP -NonI -W Hidden -Command ""Invoke-"
		$a_00_2 = {65 78 65 63 20 2b 20 22 45 78 70 72 65 73 73 69 6f 6e } //1 exec + "Expression
		$a_00_3 = {49 4f 2e 4d 65 6d 6f 72 79 53 74 72 65 61 6d 20 28 2c 24 28 5b 43 6f 6e 76 65 72 74 5d 3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 22 } //1 IO.MemoryStream (,$([Convert]::FromBase64String"
		$a_00_4 = {65 78 65 63 20 2b 20 22 49 29 29 2e 52 65 61 64 54 6f 45 6e 64 28 29 3b 22 22 22 } //1 exec + "I)).ReadToEnd();"""
		$a_00_5 = {6e 56 64 4c 62 2b 4d 32 45 4c 37 6e 56 78 43 47 44 6a 5a 69 42 39 52 62 58 69 50 41 62 72 73 6f 73 45 43 78 58 54 52 70 65 7a 42 38 30 49 4e 71 68 4d 71 57 49 63 } //1 nVdLb+M2EL7nVxCGDjZiB9RbXiPAbrsosECxXTRpezB80INqhMqWIc
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}