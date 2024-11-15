
rule Ransom_MSIL_Filecoder_SUR_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.SUR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 61 73 68 43 61 74 2e 70 64 62 } //2 CashCat.pdb
		$a_01_1 = {43 61 73 68 43 61 74 2e 65 78 65 } //2 CashCat.exe
		$a_01_2 = {74 78 74 62 6f 78 5f 42 69 74 63 6f 69 6e 67 61 64 64 65 73 73 } //1 txtbox_Bitcoingaddess
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}