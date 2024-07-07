
rule Trojan_AndroidOS_Joker_O_MTB{
	meta:
		description = "Trojan:AndroidOS/Joker.O!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {2e 6f 73 73 2d 90 02 10 2d 31 2e 61 6c 69 79 75 6e 63 73 2e 63 6f 6d 2f 90 00 } //1
		$a_01_1 = {64 78 6f 70 74 46 69 6c 65 } //1 dxoptFile
		$a_01_2 = {62 61 6f 73 } //1 baos
		$a_01_3 = {44 65 78 43 6c 61 73 73 4c 6f 61 64 65 72 } //1 DexClassLoader
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}