
rule Ransom_MSIL_HiddenTear_DM_MTB{
	meta:
		description = "Ransom:MSIL/HiddenTear.DM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {52 61 6e 73 6f 6d 5f 46 6f 72 6d } //1 Ransom_Form
		$a_81_1 = {4b 65 79 4c 6f 67 67 65 72 20 53 74 61 72 74 65 64 } //1 KeyLogger Started
		$a_81_2 = {62 6f 74 6e 65 74 } //1 botnet
		$a_81_3 = {4f 66 66 69 63 65 20 55 70 64 61 74 65 72 } //1 Office Updater
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}