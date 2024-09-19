
rule Trojan_BAT_Bingoml_NB_MTB{
	meta:
		description = "Trojan:BAT/Bingoml.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {6d 00 61 00 73 00 71 00 75 00 65 00 72 00 61 00 64 00 65 00 2e 00 62 00 6c 00 61 00 6b 00 65 00 33 00 } //2 masquerade.blake3
		$a_01_1 = {76 00 65 00 72 00 69 00 66 00 79 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //2 verify.Properties.Resources
		$a_01_2 = {52 53 44 53 2f 46 69 51 69 54 } //2 RSDS/FiQiT
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}