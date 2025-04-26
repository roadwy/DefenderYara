
rule Trojan_Win64_BlackWidow_GVA_MTB{
	meta:
		description = "Trojan:Win64/BlackWidow.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 44 0c 20 43 32 04 13 41 88 02 4d 03 d4 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}