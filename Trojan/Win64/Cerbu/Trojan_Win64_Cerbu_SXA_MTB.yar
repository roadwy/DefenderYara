
rule Trojan_Win64_Cerbu_SXA_MTB{
	meta:
		description = "Trojan:Win64/Cerbu.SXA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {74 75 70 00 f3 0f 7f 75 ?? c7 45 ?? 2d 20 53 74 66 c7 45 ?? 61 72 c6 45 d1 } //20
		$a_03_1 = {6c 79 21 00 48 8d 4d ?? c7 45 ?? 73 75 63 63 f3 0f 7f 45 ?? c7 45 ?? 65 73 73 66 66 c7 45 ?? 75 6c c6 45 f5 } //10
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}