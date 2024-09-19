
rule Trojan_Win64_Oyster_A{
	meta:
		description = "Trojan:Win64/Oyster.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {45 58 45 00 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 2c 54 65 73 74 00 43 4f 4d 00 6f 70 65 6e 00 74 65 6d 70 00 25 73 5c } //1 塅E畲摮汬㈳攮數┠ⱳ敔瑳䌀䵏漀数n整灭─屳
	condition:
		((#a_01_0  & 1)*1) >=1
 
}