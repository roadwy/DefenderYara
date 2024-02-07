
rule Trojan_AndroidOS_DropperGen_B{
	meta:
		description = "Trojan:AndroidOS/DropperGen.B,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 76 6f 64 2f 68 6c 75 6d 2f 67 62 75 79 } //01 00  Lcom/vod/hlum/gbuy
		$a_00_1 = {61 74 74 61 63 68 42 61 73 65 43 6f 6e 74 65 78 74 } //01 00  attachBaseContext
		$a_00_2 = {6c 6f 61 64 4c 69 62 72 61 72 79 } //01 00  loadLibrary
		$a_00_3 = {6e 66 79 71 75 } //00 00  nfyqu
	condition:
		any of ($a_*)
 
}