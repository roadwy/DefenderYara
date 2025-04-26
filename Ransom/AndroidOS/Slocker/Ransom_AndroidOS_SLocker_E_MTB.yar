
rule Ransom_AndroidOS_SLocker_E_MTB{
	meta:
		description = "Ransom:AndroidOS/SLocker.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_03_0 = {07 07 54 77 10 00 15 08 02 7f 6e 20 ?? ?? 87 00 07 07 } //10
		$a_03_1 = {54 20 1f 00 54 00 22 00 6e 10 ?? ?? 00 00 0c 00 72 10 ?? ?? 00 00 0c 00 } //1
		$a_03_2 = {1a 01 75 00 6e 20 ?? ?? 10 00 0c 00 6e 10 ?? ?? 00 00 0c 00 1a 01 e1 00 } //10
		$a_03_3 = {07 78 1a 09 8e 00 6e 20 ?? ?? 98 00 0c 08 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*1+(#a_03_2  & 1)*10+(#a_03_3  & 1)*1) >=11
 
}