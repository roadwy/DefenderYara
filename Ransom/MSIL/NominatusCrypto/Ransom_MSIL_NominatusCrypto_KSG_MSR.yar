
rule Ransom_MSIL_NominatusCrypto_KSG_MSR{
	meta:
		description = "Ransom:MSIL/NominatusCrypto.KSG!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {45 00 76 00 69 00 6c 00 4e 00 6f 00 6d 00 69 00 6e 00 61 00 74 00 75 00 73 00 } //1 EvilNominatus
		$a_80_1 = {59 6f 75 72 20 46 69 6c 65 73 20 68 61 73 20 62 65 65 6e 20 45 6e 63 72 79 70 74 65 64 } //Your Files has been Encrypted  1
		$a_81_2 = {52 6f 7a 62 65 68 49 6e 76 61 64 65 72 73 2e 70 64 62 } //1 RozbehInvaders.pdb
		$a_01_3 = {2e 00 65 00 78 00 65 00 20 00 3e 00 3e 00 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00 } //1 .exe >>autorun.inf
	condition:
		((#a_00_0  & 1)*1+(#a_80_1  & 1)*1+(#a_81_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}