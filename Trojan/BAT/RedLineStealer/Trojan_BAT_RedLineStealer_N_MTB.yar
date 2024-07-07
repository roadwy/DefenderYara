
rule Trojan_BAT_RedLineStealer_N_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.N!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 25 16 1f 90 01 01 9d 6f 90 01 01 00 00 0a 13 05 16 13 06 90 00 } //2
		$a_03_1 = {25 23 00 00 00 00 00 00 3e 40 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 00 25 16 6f 90 01 01 00 00 0a 00 25 73 90 01 01 00 00 0a 25 20 66 0c a8 02 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}