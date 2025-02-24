
rule Trojan_Win64_Rhadamanthys_IPK_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.IPK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 41 0f 6e 54 05 fc 66 41 0f 6e 5c 05 00 66 0f 60 d6 66 0f 61 d6 66 0f 60 de 66 0f 61 de 66 0f ef ca 66 0f ef c3 48 83 c0 10 66 0f 6f d9 66 0f 6f d0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}