
rule Trojan_BAT_AgentTesla_NER_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 05 00 "
		
	strings :
		$a_03_0 = {02 06 72 01 00 00 70 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a de 07 90 00 } //05 00 
		$a_03_1 = {07 08 18 5b 02 08 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 0a 9c 08 18 58 0c 08 06 32 e4 90 00 } //01 00 
		$a_01_2 = {4e 00 66 00 68 00 73 00 7a 00 6d 00 63 00 73 00 64 00 6b 00 } //01 00  Nfhszmcsdk
		$a_01_3 = {4b 00 44 00 45 00 20 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 73 00 } //00 00  KDE Softwares
	condition:
		any of ($a_*)
 
}