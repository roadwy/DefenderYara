
rule Trojan_Win64_Simda_EB_MTB{
	meta:
		description = "Trojan:Win64/Simda.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 07 00 "
		
	strings :
		$a_01_0 = {4c 21 5d 80 49 c7 c1 ea d0 00 00 49 81 c1 87 8c 00 00 4d 89 de 4d 89 e1 4d 11 ce 67 41 81 2f a9 87 70 5f 4c 8b 4d e8 } //00 00 
	condition:
		any of ($a_*)
 
}