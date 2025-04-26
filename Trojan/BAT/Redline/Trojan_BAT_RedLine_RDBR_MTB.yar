
rule Trojan_BAT_RedLine_RDBR_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDBR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {34 63 30 35 39 38 30 62 2d 35 32 62 64 2d 34 32 38 34 2d 38 61 35 65 2d 38 33 31 39 63 37 66 35 61 35 61 30 } //1 4c05980b-52bd-4284-8a5e-8319c7f5a5a0
		$a_01_1 = {4d 6a 6d 62 6a 62 76 79 65 } //1 Mjmbjbvye
		$a_01_2 = {56 00 7a 00 66 00 73 00 75 00 64 00 79 00 71 00 78 00 79 00 65 00 6f 00 74 00 78 00 71 00 78 00 } //1 Vzfsudyqxyeotxqx
		$a_01_3 = {4c 00 64 00 6d 00 77 00 68 00 74 00 61 00 66 00 68 00 63 00 6f 00 } //1 Ldmwhtafhco
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}