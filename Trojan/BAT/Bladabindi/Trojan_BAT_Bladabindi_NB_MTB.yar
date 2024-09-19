
rule Trojan_BAT_Bladabindi_NB_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 2f 00 00 0a 0b 11 06 1f 78 91 13 05 38 50 ff ff ff 06 17 58 0a 1f 6b 0d 20 ef 00 00 00 0c 20 cd 02 00 00 08 09 19 5a 59 30 12 11 07 1f 18 93 20 b4 86 00 00 59 13 05 38 25 ff ff ff 16 2b f6 11 07 20 a6 00 00 00 93 20 fe 9c 00 00 59 13 05 38 0d ff ff ff 07 74 09 00 00 01 2a 11 07 1f 71 93 20 7f 4e 00 00 59 13 05 } //5
		$a_01_1 = {42 50 4e 49 47 4c 57 5a 48 41 51 4a } //1 BPNIGLWZHAQJ
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}