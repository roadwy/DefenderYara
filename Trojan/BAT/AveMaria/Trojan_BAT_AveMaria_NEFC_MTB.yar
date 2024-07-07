
rule Trojan_BAT_AveMaria_NEFC_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEFC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 "
		
	strings :
		$a_03_0 = {09 11 05 9a 13 09 11 04 11 09 1f 10 28 90 01 01 00 00 0a b4 6f 90 01 01 00 00 0a 00 11 05 17 d6 13 05 00 11 05 09 8e 69 fe 04 13 0a 11 0a 2d d4 28 90 01 01 00 00 0a 11 04 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 13 06 11 06 6f 90 01 01 00 00 0a 16 9a 13 07 11 07 90 00 } //10
		$a_01_1 = {4e 00 75 00 64 00 65 00 5f 00 50 00 68 00 6f 00 74 00 6f 00 73 00 } //2 Nude_Photos
		$a_01_2 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 } //2 Invoke
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=14
 
}