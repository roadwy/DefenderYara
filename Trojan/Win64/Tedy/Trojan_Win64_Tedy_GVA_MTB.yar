
rule Trojan_Win64_Tedy_GVA_MTB{
	meta:
		description = "Trojan:Win64/Tedy.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 30 44 0e 0b 41 02 44 0e 0b e2 f4 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}