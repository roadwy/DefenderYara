
rule Trojan_BAT_QuasarRAT_BN_MTB{
	meta:
		description = "Trojan:BAT/QuasarRAT.BN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {01 25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 6f } //2
		$a_03_1 = {0e 04 05 6f ?? 00 00 0a 59 0a 06 05 28 ?? 00 00 06 2a } //1
		$a_01_2 = {0a 07 17 58 0b } //1
		$a_03_3 = {0c 07 08 28 ?? 00 00 06 d0 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=5
 
}