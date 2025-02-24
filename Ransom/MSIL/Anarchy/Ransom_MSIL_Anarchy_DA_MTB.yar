
rule Ransom_MSIL_Anarchy_DA_MTB{
	meta:
		description = "Ransom:MSIL/Anarchy.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {41 6c 6c 20 6f 66 20 79 6f 75 72 20 66 69 6c 65 73 20 67 6f 74 20 65 6e 63 72 79 70 74 65 64 } //All of your files got encrypted  1
		$a_80_1 = {2a 5f 61 6e 61 72 63 68 79 } //*_anarchy  1
		$a_80_2 = {50 61 79 20 61 20 72 61 6e 73 6f 6d } //Pay a ransom  1
		$a_80_3 = {45 6e 63 72 79 70 74 46 69 6c 65 } //EncryptFile  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}