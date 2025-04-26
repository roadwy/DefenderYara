
rule Ransom_MSIL_McBurglar_GWT_MTB{
	meta:
		description = "Ransom:MSIL/McBurglar.GWT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_03_0 = {11 04 1a 6f ?? ?? ?? 0a 00 07 06 16 06 8e 69 6f ?? ?? ?? 0a 00 07 11 04 6f ?? ?? ?? 0a 17 73 ?? ?? ?? 0a 13 06 02 19 73 ?? ?? ?? 0a 13 07 20 00 00 10 00 8d 23 00 00 01 13 08 } //10
		$a_80_1 = {52 45 41 44 4d 45 2d 4d 43 42 55 52 47 4c 41 52 2e 74 78 74 } //README-MCBURGLAR.txt  1
		$a_01_2 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //1 CreateEncryptor
		$a_80_3 = {4d 43 42 2e 70 64 62 } //MCB.pdb  1
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1+(#a_01_2  & 1)*1+(#a_80_3  & 1)*1) >=13
 
}