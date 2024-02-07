
rule TrojanDownloader_O97M_EncDoc_RVH_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.RVH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 28 22 70 69 6e 67 20 67 6f 6f 67 6c 65 2e 63 6f 6d 3b 22 20 2b 20 45 44 66 50 35 29 } //01 00  = ("ping google.com;" + EDfP5)
		$a_01_1 = {2e 53 68 61 70 65 73 28 31 29 2e 54 65 78 74 46 72 61 6d 65 2e 43 68 61 72 61 63 74 65 72 73 2e 54 65 78 74 } //01 00  .Shapes(1).TextFrame.Characters.Text
		$a_01_2 = {43 61 6c 6c 42 79 4e 61 6d 65 28 4e 41 4d 45 4d 45 2e 48 41 66 77 47 28 29 2c 20 54 65 43 42 45 28 29 2c 20 56 62 4d 65 74 68 6f 64 2c 20 4a 47 46 4d 28 29 2c 20 6a 69 62 4e 59 28 29 2c 20 4e 75 6c 6c 2c 20 4e 75 6c 6c 2c 20 30 29 } //01 00  CallByName(NAMEME.HAfwG(), TeCBE(), VbMethod, JGFM(), jibNY(), Null, Null, 0)
		$a_01_3 = {22 70 22 20 2b 20 45 44 66 50 36 } //00 00  "p" + EDfP6
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_EncDoc_RVH_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.RVH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 69 6e 67 20 67 6f 6f 67 6c 65 2e 63 6f 6d 3b 22 20 2b 20 65 65 65 65 77 } //01 00  ping google.com;" + eeeew
		$a_03_1 = {43 61 6c 6c 42 79 4e 61 6d 65 28 6b 6c 73 61 64 28 29 2c 20 52 61 6e 67 65 28 22 43 38 22 29 2e 4e 6f 74 65 54 65 78 74 2c 20 56 62 4d 65 74 68 6f 64 2c 20 90 02 06 28 30 29 2c 20 90 1b 00 28 31 29 2c 20 90 1b 00 28 32 29 2c 20 90 1b 00 28 33 29 2c 20 90 1b 00 28 34 29 29 90 00 } //01 00 
		$a_01_2 = {47 65 74 4f 62 6a 65 63 74 28 52 61 6e 67 65 28 22 43 37 22 29 2e 4e 6f 74 65 54 65 78 74 29 } //01 00  GetObject(Range("C7").NoteText)
		$a_01_3 = {6e 65 77 53 74 72 20 26 20 4d 69 64 28 73 74 72 2c 20 73 74 72 4c 65 6e 20 2d 20 28 69 20 2d 20 31 29 2c 20 31 29 } //00 00  newStr & Mid(str, strLen - (i - 1), 1)
	condition:
		any of ($a_*)
 
}