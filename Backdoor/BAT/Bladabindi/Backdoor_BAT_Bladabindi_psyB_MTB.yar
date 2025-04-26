
rule Backdoor_BAT_Bladabindi_psyB_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.psyB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5e 14 16 9a 26 16 2d f9 14 0a 28 03 01 00 06 39 2b 00 00 00 72 03 00 00 70 72 a2 00 00 70 28 9e } //1
		$a_01_1 = {04 0a 16 6a 0b 28 aa 00 00 0a 1a 40 14 00 00 00 06 28 aa 00 00 0a 18 5a 28 ab 00 00 0a 6a 0b 38 0e 00 00 00 06 28 aa 00 00 0a 18 5a 28 ac 00 00 0a 0b 7e 28 00 00 04 07 8c 61 00 00 01 6f ad 00 00 0a 0c 08 39 c4 00 00 00 08 a5 16 00 00 02 0d } //1
		$a_03_2 = {14 16 9a 26 16 2d f9 fe 09 00 00 6f ?? ?? ?? 0a 2a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}