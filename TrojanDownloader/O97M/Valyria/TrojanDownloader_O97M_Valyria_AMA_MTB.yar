
rule TrojanDownloader_O97M_Valyria_AMA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Valyria.AMA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 65 74 20 6a 62 78 69 6e 73 74 72 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 22 5a 3a 5c 73 79 73 63 61 6c 6c 73 5c 30 5f 22 20 26 20 49 6e 74 28 52 6e 64 20 2a 20 31 30 30 30 30 20 2b 20 31 30 30 30 30 29 20 26 20 22 2e 76 62 61 2e 63 73 76 22 2c 20 54 72 75 65 2c 20 54 72 75 65 29 } //6 Set jbxinstr = CreateObject("Scripting.FileSystemObject").CreateTextFile("Z:\syscalls\0_" & Int(Rnd * 10000 + 10000) & ".vba.csv", True, True)
		$a_01_1 = {53 65 74 20 6a 62 78 58 6d 6c 4e 6f 64 65 4f 62 20 3d 20 6a 62 78 58 6d 6c 4f 62 2e 63 72 65 61 74 65 45 6c 65 6d 65 6e 74 28 22 62 36 34 22 29 } //2 Set jbxXmlNodeOb = jbxXmlOb.createElement("b64")
		$a_01_2 = {6a 62 78 58 6d 6c 4e 6f 64 65 4f 62 2e 64 61 74 61 54 79 70 65 20 3d 20 22 62 69 6e 2e 62 61 73 65 36 34 22 } //1 jbxXmlNodeOb.dataType = "bin.base64"
		$a_01_3 = {4a 62 78 42 36 34 45 6e 63 6f 64 65 20 3d 20 52 65 70 6c 61 63 65 28 6a 62 78 58 6d 6c 4e 6f 64 65 4f 62 2e 54 65 78 74 2c 20 76 62 4c 66 2c 20 22 22 29 } //1 JbxB64Encode = Replace(jbxXmlNodeOb.Text, vbLf, "")
	condition:
		((#a_01_0  & 1)*6+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=10
 
}