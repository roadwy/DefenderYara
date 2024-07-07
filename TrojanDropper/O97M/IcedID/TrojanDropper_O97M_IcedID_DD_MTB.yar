
rule TrojanDropper_O97M_IcedID_DD_MTB{
	meta:
		description = "TrojanDropper:O97M/IcedID.DD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {62 71 20 22 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 76 61 72 69 61 62 6c 65 43 6f 6d 70 73 46 75 6e 63 2e 68 74 61 22 } //1 bq "c:\programdata\variableCompsFunc.hta"
		$a_01_1 = {52 65 70 6c 61 63 65 28 74 6f 43 6f 6d 70 61 72 65 48 74 6d 6c 2c 20 22 61 79 69 6b 22 2c 20 22 22 29 } //1 Replace(toCompareHtml, "ayik", "")
		$a_01_2 = {74 6f 42 72 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 52 61 6e 67 65 2e 54 65 78 74 29 } //1 toBr(ActiveDocument.Range.Text)
		$a_01_3 = {53 68 65 6c 6c 20 22 63 6d 22 20 26 20 63 6f 6d 70 61 72 65 43 6f 72 65 20 26 20 69 46 75 6e 63 } //1 Shell "cm" & compareCore & iFunc
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}