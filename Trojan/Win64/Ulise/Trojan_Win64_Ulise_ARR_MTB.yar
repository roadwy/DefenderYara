
rule Trojan_Win64_Ulise_ARR_MTB{
	meta:
		description = "Trojan:Win64/Ulise.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 04 01 33 44 24 28 8b 4c 24 20 48 8b 54 24 68 88 04 0a } //6
		$a_01_1 = {48 8b 4c 24 60 8b 49 1c 03 08 8b c1 99 81 e2 } //4
	condition:
		((#a_01_0  & 1)*6+(#a_01_1  & 1)*4) >=10
 
}