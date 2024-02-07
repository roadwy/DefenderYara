
rule Trojan_AndroidOS_Spynote_I{
	meta:
		description = "Trojan:AndroidOS/Spynote.I,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {47 65 74 52 65 71 75 69 65 72 64 50 72 69 6d 73 } //02 00  GetRequierdPrims
		$a_01_1 = {54 6f 41 73 6b 4e 65 77 } //02 00  ToAskNew
		$a_01_2 = {5f 61 73 6b 5f 72 65 6d 6f 76 65 5f } //02 00  _ask_remove_
		$a_01_3 = {41 73 6b 4b 65 79 50 72 69 6d } //00 00  AskKeyPrim
	condition:
		any of ($a_*)
 
}