
rule Ransom_MSIL_Choas_GVA_MTB{
	meta:
		description = "Ransom:MSIL/Choas.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6d fe 0e 23 00 fe 0c 1f 00 fe 0c 1f 00 1f 12 62 61 fe 0e 1f 00 fe 0c 1f 00 fe 0c 20 00 58 fe 0e 1f 00 fe 0c 1f 00 fe 0c 1f 00 17 64 61 fe 0e 1f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}