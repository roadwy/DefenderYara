
rule Ransom_MSIL_HiddenTear_SWA_MTB{
	meta:
		description = "Ransom:MSIL/HiddenTear.SWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 07 00 05 00 00 "
		
	strings :
		$a_80_0 = {6d 72 6d 61 6c 72 61 6e 73 6f 6d 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 6d 72 6d 61 6c 72 61 6e 73 6f 6d 2e 70 64 62 } //mrmalransom\obj\Release\mrmalransom.pdb  2
		$a_80_1 = {4d 72 2e 20 4d 61 6c 77 61 72 65 } //Mr. Malware  2
		$a_80_2 = {24 37 33 30 63 32 36 30 61 2d 61 36 35 62 2d 34 38 31 39 2d 38 37 36 63 2d 36 37 35 38 61 62 38 33 36 30 37 31 } //$730c260a-a65b-4819-876c-6758ab836071  2
		$a_80_3 = {6d 72 6d 61 6c 72 61 6e 73 6f 6d 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //mrmalransom.Properties.Resources  2
		$a_80_4 = {59 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 21 } //Your computer files have been encrypted!  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*1) >=7
 
}