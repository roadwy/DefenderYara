
rule Trojan_AndroidOS_FakeInst_F{
	meta:
		description = "Trojan:AndroidOS/FakeInst.F,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {77 75 6a 58 71 64 74 42 75 68 4a 78 68 75 71 74 } //01 00  wujXqdtBuhJxhuqt
		$a_01_1 = {78 71 64 74 42 75 70 75 69 69 71 77 75 } //01 00  xqdtBupuiiqwu
		$a_01_2 = {43 6f 65 73 71 42 4f 6a 79 73 69 4e 75 4f } //00 00  CoesqBOjysiNuO
	condition:
		any of ($a_*)
 
}