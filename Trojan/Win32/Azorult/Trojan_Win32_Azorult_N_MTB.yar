
rule Trojan_Win32_Azorult_N_MTB{
	meta:
		description = "Trojan:Win32/Azorult.N!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {c7 04 24 00 00 00 00 83 04 24 04 8b 0c 24 8b 44 24 0c d3 e0 8b 4c 24 08 89 01 59 c2 08 00 } //5
		$a_01_1 = {8b 44 24 0c 8b 4c 24 04 c1 e8 05 89 01 89 44 24 0c 8b 44 24 0c 03 44 24 08 89 44 24 0c 8b 44 24 0c 89 01 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}