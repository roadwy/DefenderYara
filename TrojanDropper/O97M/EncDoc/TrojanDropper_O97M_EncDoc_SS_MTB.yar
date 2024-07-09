
rule TrojanDropper_O97M_EncDoc_SS_MTB{
	meta:
		description = "TrojanDropper:O97M/EncDoc.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {62 64 66 64 66 20 3d 20 46 56 66 4e 2e 4f 70 65 6e 28 76 30 64 66 20 2b 20 22 5c 45 54 74 46 64 2e 62 61 74 22 29 } //1 bdfdf = FVfN.Open(v0df + "\ETtFd.bat")
		$a_03_1 = {69 56 4d 47 20 3d 20 45 6e 76 69 72 6f 6e 28 22 41 70 70 44 61 74 61 22 29 [0-03] 45 6e 64 20 46 75 6e 63 74 69 6f 6e } //1
		$a_01_2 = {3d 20 52 61 6e 67 65 28 22 41 31 30 35 22 29 2e 56 61 6c 75 65 20 2b 20 22 20 22 20 2b 20 52 61 6e 67 65 28 22 41 31 30 34 22 29 2e 56 61 6c 75 65 20 2b 20 52 61 6e 67 65 28 22 41 31 30 33 22 29 2e 56 61 6c 75 65 20 2b 20 22 20 2d 22 20 2b 20 52 61 6e 67 65 28 22 41 31 30 30 22 29 2e 56 61 6c 75 65 } //1 = Range("A105").Value + " " + Range("A104").Value + Range("A103").Value + " -" + Range("A100").Value
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}