
rule Trojan_BAT_Bladabindi_ABF_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.ABF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_00_0 = {08 04 07 6e 04 8e b7 6a 5d b7 91 d7 11 05 07 84 95 d7 6e 20 ff 00 00 00 6a 5f b8 0c 11 05 07 84 95 13 06 11 05 07 84 11 05 08 84 95 9e 11 05 08 84 11 06 9e 07 17 d7 0b 07 20 ff 00 00 00 36 c0 } //10
		$a_80_1 = {45 78 65 63 42 79 74 65 73 } //ExecBytes  3
		$a_80_2 = {50 72 6f 70 65 72 5f 52 43 34 } //Proper_RC4  3
		$a_80_3 = {42 65 74 61 2e 43 68 61 72 6c 69 65 } //Beta.Charlie  3
		$a_80_4 = {45 6d 69 74 } //Emit  3
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3) >=22
 
}