
rule TrojanDownloader_O97M_Obfuse_YAG_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.YAG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4f 70 65 6e 20 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 72 65 22 20 26 20 6b 4f 2e 54 61 67 } //1 Open "C:\ProgramData\re" & kO.Tag
		$a_00_1 = {4f 70 65 6e 20 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 50 49 59 52 46 46 6a 6a 68 46 47 72 66 74 66 67 46 59 67 72 66 74 68 56 66 59 48 74 72 66 47 68 79 68 66 22 20 46 6f 72 20 42 69 6e 61 72 79 20 41 73 } //1 Open "C:\ProgramData\PIYRFFjjhFGrftfgFYgrfthVfYHtrfGhyhf" For Binary As
		$a_00_2 = {53 65 74 20 70 4f 4c 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 6b 4f 2e 6a 45 2e 54 61 67 29 } //1 Set pOL = CreateObject(kO.jE.Tag)
		$a_00_3 = {70 4f 4c 2e 45 78 65 63 20 22 65 78 70 6c 6f 72 65 72 2e 65 78 65 20 22 20 26 20 66 49 4f 4c } //1 pOL.Exec "explorer.exe " & fIOL
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}