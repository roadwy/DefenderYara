
rule Trojan_BAT_Formbook_DX_MTB{
	meta:
		description = "Trojan:BAT/Formbook.DX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {24 33 65 61 38 31 36 38 30 2d 61 34 30 36 2d 34 39 35 65 2d 38 37 31 34 2d 36 66 61 31 33 33 61 64 63 34 62 39 } //1 $3ea81680-a406-495e-8714-6fa133adc4b9
		$a_81_1 = {46 6d 67 45 64 69 74 2e 44 42 2e 72 65 73 6f 75 72 63 65 73 } //1 FmgEdit.DB.resources
		$a_81_2 = {46 6d 67 45 64 69 74 2e 63 61 72 64 5f 73 77 61 70 2e 72 65 73 6f 75 72 63 65 73 } //1 FmgEdit.card_swap.resources
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //1 FromBase64CharArray
		$a_81_4 = {4c 6f 61 64 46 72 6f 6d 46 69 6c 65 } //1 LoadFromFile
		$a_81_5 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerBrowsableAttribute
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}