
rule Trojan_BAT_AveMaria_N_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.N!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {56 00 00 00 01 00 00 00 01 00 00 00 05 00 00 00 0e 00 00 00 01 00 00 00 01 00 00 00 08 00 00 00 19 00 00 00 32 00 00 00 02 00 00 00 } //1
		$a_01_1 = {57 f5 b6 3d 09 1e 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 64 00 00 00 1e 00 00 00 3b 00 00 00 93 00 00 00 99 00 00 00 8a 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}