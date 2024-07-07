
rule Trojan_Win64_Rozena_NI_MTB{
	meta:
		description = "Trojan:Win64/Rozena.NI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {74 26 48 89 5c 24 90 01 01 48 89 4c 24 90 01 01 48 89 44 24 90 01 01 48 89 cb e8 18 96 fa ff 48 8b 44 24 20 90 00 } //3
		$a_03_1 = {e8 bb 95 fa ff 48 8b 44 24 90 01 01 48 8b 5c 24 90 01 01 48 89 5c 24 90 01 01 e8 87 a8 00 00 48 83 c4 20 90 00 } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}