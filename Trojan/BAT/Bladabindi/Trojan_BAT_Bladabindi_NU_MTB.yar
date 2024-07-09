
rule Trojan_BAT_Bladabindi_NU_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.NU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 08 07 6f ?? ?? ?? 0a 00 08 18 6f ?? ?? ?? 0a 00 08 6f ?? ?? ?? 0a 02 16 02 8e 69 6f ?? ?? ?? 0a 0d 09 13 04 2b } //1
		$a_01_1 = {57 95 a2 29 09 0b 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 56 00 00 00 09 00 00 00 0f 00 00 00 17 00 00 00 05 00 00 00 76 00 00 00 18 00 00 00 01 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}