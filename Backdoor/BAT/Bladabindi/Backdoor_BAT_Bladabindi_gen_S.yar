
rule Backdoor_BAT_Bladabindi_gen_S{
	meta:
		description = "Backdoor:BAT/Bladabindi.gen!S,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {1f 6e 9d 06 1f ?? 1f 74 9d 06 1f ?? 1f 56 9d 06 1f ?? 1f 65 9d 06 1f ?? 1f 72 9d 06 1f ?? 1f 73 9d 06 1f ?? 1f 69 9d 06 1f ?? 1f 6f 9d 06 1f ?? 1f 6e 9d 06 1f ?? 1f 5c 9d 06 1f ?? 1f 52 9d 06 1f ?? 1f 75 9d 06 1f ?? 1f 6e } //1
		$a_00_1 = {13 15 11 15 16 1f 2e 9d 11 15 17 1f 2e 9d 11 15 28 67 00 00 06 16 28 e4 00 00 06 16 33 0a 20 88 13 00 00 28 02 01 00 06 } //10
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*10) >=10
 
}