
rule Trojan_Win64_IcedID_BR_MTB{
	meta:
		description = "Trojan:Win64/IcedID.BR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {42 36 62 42 6f 48 61 50 6a 67 5a } //1 B6bBoHaPjgZ
		$a_01_1 = {4a 50 77 46 51 58 47 } //1 JPwFQXG
		$a_01_2 = {4d 36 74 70 43 4b 34 34 53 63 4d } //1 M6tpCK44ScM
		$a_01_3 = {52 75 6e 4f 62 6a 65 63 74 } //1 RunObject
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}