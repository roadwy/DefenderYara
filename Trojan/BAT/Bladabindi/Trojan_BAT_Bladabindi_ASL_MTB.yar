
rule Trojan_BAT_Bladabindi_ASL_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.ASL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 04 11 05 8f 90 01 01 00 00 01 25 71 90 01 01 00 00 01 11 05 0e 04 58 20 ff 00 00 00 5f d2 61 d2 81 90 01 01 00 00 01 11 05 17 58 13 05 11 05 04 32 90 00 } //4
		$a_01_1 = {63 00 33 00 52 00 31 00 59 00 6e 00 4e 00 30 00 64 00 57 00 49 00 3d 00 } //1 c3R1YnN0dWI=
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}