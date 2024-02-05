
rule Trojan_BAT_Dcstl_ABCQ_MTB{
	meta:
		description = "Trojan:BAT/Dcstl.ABCQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {09 11 04 91 13 05 00 07 08 11 05 03 61 d2 9c 08 17 58 0c 00 11 04 17 58 13 04 11 04 09 8e 69 32 df } //01 00 
		$a_01_1 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //01 00 
		$a_01_2 = {43 72 79 69 6e 67 57 6f 6c 66 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}