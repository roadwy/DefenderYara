
rule Trojan_AndroidOS_Hqwar_L_MTB{
	meta:
		description = "Trojan:AndroidOS/Hqwar.L!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 6d 65 6d 2f 69 6e 73 74 61 6c 6c 64 72 6f 70 73 65 73 73 69 6f 6e } //1 com/mem/installdropsession
		$a_03_1 = {05 00 0c 05 6e 10 ?? 02 05 00 0c 05 22 00 ?? ?? 12 11 70 20 ?? 02 10 00 6e 20 ?? 02 05 00 0a 00 6e 20 ?? 02 05 00 0c 04 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}