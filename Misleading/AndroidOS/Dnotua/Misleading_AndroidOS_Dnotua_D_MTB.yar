
rule Misleading_AndroidOS_Dnotua_D_MTB{
	meta:
		description = "Misleading:AndroidOS/Dnotua.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 63 6e 61 6e 7a 68 69 2e 63 6f 6d } //01 00  .cnanzhi.com
		$a_01_1 = {63 6f 6d 2f 65 78 61 6d 70 6c 65 2f 61 64 6d 69 6e 69 73 74 72 61 74 6f 72 2f } //01 00  com/example/administrator/
		$a_01_2 = {6c 6f 61 64 55 72 6c } //01 00  loadUrl
		$a_01_3 = {73 68 6f 75 6c 64 4f 76 65 72 72 69 64 65 55 72 6c 4c 6f 61 64 69 6e 67 } //00 00  shouldOverrideUrlLoading
	condition:
		any of ($a_*)
 
}