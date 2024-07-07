
rule TrojanDownloader_O97M_Powdow_DICE_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.DICE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {62 71 20 22 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 74 6f 54 6f 56 61 72 69 61 62 6c 65 2e 68 74 61 22 2c 20 22 64 20 2f 63 20 22 } //1 bq "c:\programdata\toToVariable.hta", "d /c "
		$a_01_1 = {69 46 6f 72 20 3d 20 52 65 70 6c 61 63 65 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 52 61 6e 67 65 2e 54 65 78 74 2c 20 76 61 72 69 61 62 6c 65 46 6f 72 48 74 6d 6c 2c 20 22 22 29 } //1 iFor = Replace(ActiveDocument.Range.Text, variableForHtml, "")
		$a_01_2 = {53 68 65 6c 6c 20 22 63 6d 22 20 26 20 69 43 6f 6d 70 73 49 20 26 20 63 6f 64 65 43 6f 64 65 56 61 72 } //1 Shell "cm" & iCompsI & codeCodeVar
		$a_01_3 = {50 72 69 6e 74 20 23 31 2c 20 69 46 6f 72 28 22 78 70 67 6f 64 22 29 } //1 Print #1, iFor("xpgod")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}