
rule Backdoor_BAT_Remcos_AAYU_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.AAYU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 05 03 02 8e 69 6f ?? 01 00 0a 0a 06 28 ?? 01 00 0a 00 06 0b 2b 00 07 2a } //3
		$a_01_1 = {76 00 73 00 4c 00 68 00 4c 00 68 00 4a 00 42 00 55 00 43 00 69 00 76 00 77 00 4d 00 77 00 45 00 55 00 4d 00 54 00 78 00 45 00 42 00 41 00 76 00 54 00 43 00 55 00 51 00 4a 00 68 00 76 00 43 00 44 00 79 00 77 00 5a 00 72 00 70 00 55 00 66 00 68 00 66 00 } //1 vsLhLhJBUCivwMwEUMTxEBAvTCUQJhvCDywZrpUfhf
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}