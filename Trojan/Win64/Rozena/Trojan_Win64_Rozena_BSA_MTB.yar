
rule Trojan_Win64_Rozena_BSA_MTB{
	meta:
		description = "Trojan:Win64/Rozena.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_01_0 = {e9 5a 5e 0e 00 e9 45 4e 0c 00 e9 b0 3a 08 00 e9 7b 45 1e 00 e9 b6 59 0d 00 } //8
	condition:
		((#a_01_0  & 1)*8) >=8
 
}