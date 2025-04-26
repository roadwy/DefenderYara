
rule Trojan_BAT_Formbook_DA_MTB{
	meta:
		description = "Trojan:BAT/Formbook.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {24 39 35 36 37 38 62 62 32 2d 35 34 35 32 2d 34 36 36 65 2d 38 30 39 39 2d 30 62 31 35 39 36 39 61 64 65 31 39 } //1 $95678bb2-5452-466e-8099-0b15969ade19
		$a_81_1 = {50 4f 53 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //1 POS.My.Resources
		$a_81_2 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_81_3 = {67 65 74 5f 43 6c 69 70 62 6f 61 72 64 } //1 get_Clipboard
		$a_81_4 = {67 65 74 5f 57 68 69 74 65 53 6d 6f 6b 65 } //1 get_WhiteSmoke
		$a_81_5 = {46 61 63 65 62 6f 6f 6b } //1 Facebook
		$a_81_6 = {50 61 73 73 77 6f 72 64 } //1 Password
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}