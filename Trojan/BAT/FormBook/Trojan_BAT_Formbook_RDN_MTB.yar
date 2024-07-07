
rule Trojan_BAT_Formbook_RDN_MTB{
	meta:
		description = "Trojan:BAT/Formbook.RDN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 63 37 66 61 64 30 33 2d 38 31 36 65 2d 34 33 32 63 2d 39 62 39 32 2d 30 30 31 66 32 64 34 39 38 38 38 35 } //1 cc7fad03-816e-432c-9b92-001f2d498885
		$a_01_1 = {73 65 72 76 65 72 31 } //1 server1
		$a_01_2 = {49 6d 70 6f 72 74 61 6e 74 20 53 79 73 74 65 6d 20 46 69 6c 65 } //1 Important System File
		$a_01_3 = {53 79 73 20 66 69 6c 65 } //1 Sys file
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}