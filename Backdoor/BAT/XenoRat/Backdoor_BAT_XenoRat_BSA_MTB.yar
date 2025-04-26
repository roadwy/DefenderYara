
rule Backdoor_BAT_XenoRat_BSA_MTB{
	meta:
		description = "Backdoor:BAT/XenoRat.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {78 65 6e 6f 20 72 61 74 20 63 6c 69 65 6e 74 } //10 xeno rat client
		$a_01_1 = {1b 30 06 00 84 0b 00 00 10 00 00 11 12 00 14 7d 04 00 00 04 14 0b 72 64 05 00 70 0c 08 18 28 32 00 00 0a 28 33 00 00 0a 16 28 34 00 00 0a 26 21 00 60 40 00 00 00 00 00 e0 0d 20 b7 50 00 00 13 04 11 04 8d } //5
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}
rule Backdoor_BAT_XenoRat_BSA_MTB_2{
	meta:
		description = "Backdoor:BAT/XenoRat.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_01_0 = {78 65 6e 6f 20 72 61 74 20 63 6c 69 65 6e 74 } //10 xeno rat client
		$a_01_1 = {78 65 6e 6f 5f 72 61 74 5f 63 6c 69 65 6e 74 } //10 xeno_rat_client
		$a_01_2 = {5c 78 65 6e 6f 2d 72 61 74 5c 50 6c 75 67 69 6e 73 } //10 \xeno-rat\Plugins
		$a_01_3 = {53 65 6e 64 41 73 79 6e 63 } //6 SendAsync
		$a_01_4 = {49 41 73 79 6e 63 53 74 61 74 65 4d 61 63 68 69 6e 65 } //6 IAsyncStateMachine
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*6+(#a_01_4  & 1)*6) >=22
 
}