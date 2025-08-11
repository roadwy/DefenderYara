
rule Trojan_Win64_Latrodectus_GVA_MTB{
	meta:
		description = "Trojan:Win64/Latrodectus.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c5 dd fd e6 c5 d5 fd ef 44 30 14 0f 66 0f 70 fe ?? 66 0f 70 fd ?? 66 0f f1 da 66 0f f1 ec } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}