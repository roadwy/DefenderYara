
rule TrojanDownloader_O97M_Obfuse_PCA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PCA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_00_0 = {6c 69 63 65 6e 31 20 3d 20 22 66 6c 22 20 2b 20 22 73 74 22 20 2b 20 22 75 64 69 22 20 2b 20 22 6f 22 20 2b 20 22 2e 6a 22 20 2b 20 22 73 22 } //1 licen1 = "fl" + "st" + "udi" + "o" + ".j" + "s"
		$a_00_1 = {63 6c 6f 73 6d 31 20 3d 20 22 77 73 22 20 2b 20 22 63 72 22 20 2b 20 22 69 22 20 2b 20 22 70 22 20 2b 20 22 74 20 22 20 2b 20 6c 69 63 65 6e 31 } //1 closm1 = "ws" + "cr" + "i" + "p" + "t " + licen1
		$a_00_2 = {53 65 74 20 66 73 6f 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 } //1 Set fso = CreateObject("Scripting.FileSystemObject")
		$a_00_3 = {53 65 74 20 66 6f 20 3d 20 66 73 6f 2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 6c 69 63 65 6e 31 29 } //1 Set fo = fso.CreateTextFile(licen1)
		$a_00_4 = {66 6f 2e 57 72 69 74 65 4c 69 6e 65 20 69 67 6e 74 74 65 78 74 } //1 fo.WriteLine ignttext
		$a_00_5 = {53 65 74 20 66 73 6f 20 3d 20 4e 6f 74 68 69 6e 67 } //1 Set fso = Nothing
		$a_00_6 = {69 67 6e 74 74 65 78 74 20 3d 20 69 67 6e 74 74 65 78 74 31 20 2b 20 69 67 6e 74 74 65 78 74 32 20 2b 20 69 67 6e 74 74 65 78 74 33 20 2b 20 69 67 6e 74 74 65 78 74 34 20 2b 20 69 67 6e 74 74 65 78 74 35 } //1 ignttext = ignttext1 + ignttext2 + ignttext3 + ignttext4 + ignttext5
		$a_00_7 = {3d 20 22 74 72 79 20 7b 57 53 63 72 69 70 74 2e 53 6c 65 65 70 28 31 34 30 30 30 29 3b 76 61 72 20 73 20 3d 20 } //1 = "try {WScript.Sleep(14000);var s = 
		$a_00_8 = {69 67 6e 74 74 65 78 74 31 35 20 3d 20 22 61 6c 28 73 29 3b 7d 20 63 61 74 63 68 28 65 72 72 29 20 7b 20 7d 22 } //1 ignttext15 = "al(s);} catch(err) { }"
		$a_00_9 = {31 30 34 2c 31 31 36 2c 31 31 36 2c 31 31 32 2c 35 38 2c 34 37 2c 34 37 2c 34 39 2c 35 37 2c 35 32 2c 34 36 2c 35 31 2c 35 35 2c 34 36 2c 35 37 2c 35 35 2c 34 36 2c 34 39 2c 35 31 2c 35 33 2c 35 38 2c 34 39 2c 34 39 2c 35 33 2c 35 33 2c 34 37 2c 33 39 2c 33 32 2c 34 33 2c 33 32 2c 36 37 2c 34 34 2c 33 32 2c 31 30 32 2c 39 37 2c 31 30 38 2c 31 31 35 } //1 104,116,116,112,58,47,47,49,57,52,46,51,55,46,57,55,46,49,51,53,58,49,49,53,53,47,39,32,43,32,67,44,32,102,97,108,115
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1) >=10
 
}