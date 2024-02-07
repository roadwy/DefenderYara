
rule TrojanDownloader_O97M_Qakbot_SHM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.SHM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 53 4f 2e 43 6f 70 79 46 69 6c 65 20 61 39 58 42 4e 2c 20 61 6a 5a 53 78 46 2c 20 31 } //01 00  FSO.CopyFile a9XBN, ajZSxF, 1
		$a_01_1 = {53 70 6c 69 74 28 61 39 48 36 34 28 66 72 6d 2e 70 61 74 68 73 2e 74 65 78 74 29 2c 20 22 7c 22 29 } //01 00  Split(a9H64(frm.paths.text), "|")
		$a_01_2 = {43 61 6c 6c 20 61 4b 33 73 69 6e 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 28 61 6f 4f 74 37 2c 20 61 56 78 68 63 2c 20 22 20 22 2c 20 53 57 5f 48 49 44 45 29 } //01 00  Call aK3sin.ShellExecute(aoOt7, aVxhc, " ", SW_HIDE)
		$a_01_3 = {61 39 48 36 34 28 66 72 6d 2e 70 61 79 6c 6f 61 64 2e 74 65 78 74 29 } //01 00  a9H64(frm.payload.text)
		$a_01_4 = {43 68 72 28 33 34 29 } //01 00  Chr(34)
		$a_01_5 = {2e 52 75 6e 20 22 61 39 34 36 38 75 22 2c 20 61 6a 5a 53 78 46 2c 20 61 46 48 6a 36 69 20 26 20 22 6d 61 74 20 3a 20 } //00 00  .Run "a9468u", ajZSxF, aFHj6i & "mat : 
	condition:
		any of ($a_*)
 
}