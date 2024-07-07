
rule Trojan_Win64_IcedID_SZA_MTB{
	meta:
		description = "Trojan:Win64/IcedID.SZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c8 8b c1 66 90 01 02 74 90 01 01 48 90 01 02 b9 90 01 04 48 90 01 02 3a c9 74 90 0a 2f 00 3a c0 74 90 01 01 89 44 24 90 01 01 48 90 01 04 33 d2 66 90 01 02 74 90 01 01 8b 4c 24 90 00 } //1
		$a_00_1 = {49 6e 69 74 } //1 Init
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}