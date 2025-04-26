
rule Trojan_BAT_Injuke_MBGO_MTB{
	meta:
		description = "Trojan:BAT/Injuke.MBGO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 06 11 05 11 20 9a 1f 10 28 ?? 00 00 0a b4 6f ?? 00 00 0a 00 11 20 17 d6 13 20 11 20 11 1f 31 df } //1
		$a_01_1 = {51 00 75 00 61 00 6e 00 4c 00 79 00 42 00 61 00 6e 00 00 11 47 00 69 00 61 00 79 00 2e 00 43 00 43 00 4d } //1
		$a_01_2 = {32 31 37 65 30 38 61 33 } //1 217e08a3
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}