
rule Ransom_MSIL_NefiCrypt_PI_MSR{
	meta:
		description = "Ransom:MSIL/NefiCrypt.PI!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4e 00 45 00 46 00 49 00 4c 00 49 00 4d 00 2d 00 44 00 45 00 43 00 52 00 59 00 50 00 54 00 2e 00 74 00 78 00 74 00 } //1 NEFILIM-DECRYPT.txt
		$a_01_1 = {66 75 6b 20 73 6f 73 6f 72 69 6e } //1 fuk sosorin
		$a_01_2 = {68 00 68 00 6f 00 77 00 20 00 74 00 6f 00 20 00 66 00 75 00 63 00 6b 00 20 00 61 00 6c 00 6c 00 20 00 74 00 68 00 65 00 20 00 77 00 6f 00 72 00 6c 00 64 00 } //1 hhow to fuck all the world
		$a_01_3 = {5c 4e 45 46 49 4c 49 4d 2e 70 64 62 } //1 \NEFILIM.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}