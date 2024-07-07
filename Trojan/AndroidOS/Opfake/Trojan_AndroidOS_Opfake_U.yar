
rule Trojan_AndroidOS_Opfake_U{
	meta:
		description = "Trojan:AndroidOS/Opfake.U,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {5b 4c 6a 63 6a 63 6c 2f 74 6e 68 6b 6b 3b } //2 [Ljcjcl/tnhkk;
		$a_01_1 = {76 6d 6b 72 76 61 75 69 6f } //2 vmkrvauio
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}