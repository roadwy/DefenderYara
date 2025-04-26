
rule Trojan_Win64_Remcos_GVA_MTB{
	meta:
		description = "Trojan:Win64/Remcos.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 01 d0 44 89 c2 31 ca 88 10 48 8b 55 10 48 8b 45 f8 48 01 d0 0f b6 00 0f b6 d0 } //3
		$a_01_1 = {48 01 d0 44 89 c2 31 ca 88 10 48 83 45 f8 01 48 8b 45 f8 48 3b 45 18 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}