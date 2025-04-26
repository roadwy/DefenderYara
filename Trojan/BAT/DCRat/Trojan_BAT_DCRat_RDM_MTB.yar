
rule Trojan_BAT_DCRat_RDM_MTB{
	meta:
		description = "Trojan:BAT/DCRat.RDM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {46 56 6f 64 75 30 6b 59 4e 56 5a 5a 35 36 47 58 6f 44 47 34 73 6a 52 65 76 46 6a 73 72 73 50 57 53 37 4f 79 53 6f 74 69 31 47 37 44 } //1 FVodu0kYNVZZ56GXoDG4sjRevFjsrsPWS7OySoti1G7D
		$a_01_1 = {6b 4d 38 4c 4c 52 47 41 39 34 } //1 kM8LLRGA94
		$a_01_2 = {6f 78 5a 32 47 63 4c 6f 76 33 56 68 51 75 32 4f 47 42 59 } //1 oxZ2GcLov3VhQu2OGBY
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}