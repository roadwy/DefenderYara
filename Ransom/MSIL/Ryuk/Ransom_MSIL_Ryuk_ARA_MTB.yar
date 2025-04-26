
rule Ransom_MSIL_Ryuk_ARA_MTB{
	meta:
		description = "Ransom:MSIL/Ryuk.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_80_0 = {72 79 75 6b 72 61 6e 73 6f 6d } //ryukransom  2
		$a_80_1 = {52 79 75 6b 45 6e 63 72 79 70 74 65 72 } //RyukEncrypter  2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2) >=4
 
}