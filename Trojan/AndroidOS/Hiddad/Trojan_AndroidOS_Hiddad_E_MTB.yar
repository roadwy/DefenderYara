
rule Trojan_AndroidOS_Hiddad_E_MTB{
	meta:
		description = "Trojan:AndroidOS/Hiddad.E!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {80 46 be f1 00 0f 15 90 01 01 09 f1 ff 37 01 38 00 23 03 f0 03 01 0d f1 18 0c 61 44 01 33 17 f8 01 2f 73 45 11 f8 08 1c 82 ea 01 02 00 f8 01 2f ef 90 01 01 dd f8 0c e0 00 23 08 f8 0e 30 b9 f1 00 0f 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}