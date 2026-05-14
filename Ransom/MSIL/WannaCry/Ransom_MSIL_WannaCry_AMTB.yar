
rule Ransom_MSIL_WannaCry_AMTB{
	meta:
		description = "Ransom:MSIL/WannaCry!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {43 3a 5c 55 73 65 72 73 5c 41 63 65 72 20 4e 69 74 72 6f 20 35 30 5c 44 65 73 6b 74 6f 70 5c 43 23 5c 57 61 6e 6e 61 43 72 79 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 50 61 79 44 61 79 2e 70 64 62 } //C:\Users\Acer Nitro 50\Desktop\C#\WannaCry\obj\Release\PayDay.pdb  1
		$a_80_1 = {49 6d 61 67 65 2e 57 4e 43 52 59 } //Image.WNCRY  1
		$a_80_2 = {57 6f 72 6b 66 6c 6f 77 2e 57 4e 43 52 59 } //Workflow.WNCRY  1
		$a_80_3 = {50 61 79 44 61 79 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //PayDay.Properties.Resources  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}