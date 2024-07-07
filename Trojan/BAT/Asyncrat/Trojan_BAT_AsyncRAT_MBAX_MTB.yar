
rule Trojan_BAT_AsyncRAT_MBAX_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.MBAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 08 07 6f 90 01 01 00 00 0a 08 18 6f 90 01 01 00 00 0a 08 6f 90 01 01 00 00 0a 02 50 16 02 50 8e 69 6f 90 01 01 00 00 0a 2a 90 00 } //1
		$a_01_1 = {43 00 6f 00 72 00 6f 00 6e 00 6f 00 76 00 69 00 72 00 75 00 73 00 2e 00 43 00 6f 00 72 00 6f 00 6e 00 6f 00 76 00 69 00 72 00 75 00 73 00 } //1 Coronovirus.Coronovirus
		$a_01_2 = {4d 00 4c 00 48 00 4a 00 66 00 44 00 44 00 44 00 53 00 5a 00 00 2f 43 00 6f 00 72 00 6f 00 6e 00 6f 00 76 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}