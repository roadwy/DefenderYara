
rule Trojan_AndroidOS_Hiddad_G_MTB{
	meta:
		description = "Trojan:AndroidOS/Hiddad.G!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {66 69 6c 65 43 6f 6d 2f 72 65 63 6f 76 65 72 2f 6b 65 65 70 } //01 00  fileCom/recover/keep
		$a_00_1 = {41 64 53 65 73 73 69 6f 6e 43 6f 6e 66 69 67 75 72 61 74 69 6f 6e } //01 00  AdSessionConfiguration
		$a_00_2 = {69 6e 6a 65 63 74 53 63 72 69 70 74 43 6f 6e 74 65 6e 74 49 6e 74 6f 48 74 6d 6c } //01 00  injectScriptContentIntoHtml
		$a_00_3 = {69 73 4f 72 57 69 6c 6c 42 65 48 69 64 64 65 6e } //00 00  isOrWillBeHidden
	condition:
		any of ($a_*)
 
}