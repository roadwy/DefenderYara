
rule Backdoor_Win32_Rabasheeta_A{
	meta:
		description = "Backdoor:Win32/Rabasheeta.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6d 61 6b 65 53 68 69 74 61 72 61 62 61 54 68 72 65 61 64 00 } //1 慭敫桓瑩牡扡呡牨慥d
		$a_01_1 = {62 69 6e 44 6f 77 6e 6c 6f 61 64 00 } //1 楢䑮睯汮慯d
		$a_01_2 = {4b 41 4b 49 4b 4f 5f 4c 45 4e 5f 4c 49 4d 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}