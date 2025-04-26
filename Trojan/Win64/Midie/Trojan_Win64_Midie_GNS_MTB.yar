
rule Trojan_Win64_Midie_GNS_MTB{
	meta:
		description = "Trojan:Win64/Midie.GNS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {04 c1 86 36 32 1a 95 2a a4 4d } //5
		$a_03_1 = {8c 11 42 36 ee 97 a4 bc ?? ?? ?? ?? cc 31 d1 32 2e 59 00 76 10 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}
rule Trojan_Win64_Midie_GNS_MTB_2{
	meta:
		description = "Trojan:Win64/Midie.GNS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {2f ef 00 72 ?? 0a d7 30 76 ?? a4 e2 ?? 30 76 ?? dc 72 ?? 30 76 ?? ac 0a 0f 30 76 ?? bc } //10
		$a_01_1 = {62 61 45 38 2e 4e 55 36 4c } //1 baE8.NU6L
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}