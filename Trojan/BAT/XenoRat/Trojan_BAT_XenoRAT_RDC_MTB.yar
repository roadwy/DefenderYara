
rule Trojan_BAT_XenoRAT_RDC_MTB{
	meta:
		description = "Trojan:BAT/XenoRAT.RDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {44 69 73 70 6c 61 79 20 44 72 69 76 65 72 20 44 69 73 70 6c 61 79 20 49 6d 70 72 6f 76 65 20 49 6e 63 } //1 Display Driver Display Improve Inc
		$a_01_1 = {48 44 69 73 70 6c 61 79 20 44 72 69 76 65 72 20 52 65 63 6f 76 65 72 79 } //1 HDisplay Driver Recovery
		$a_01_2 = {49 6d 70 6f 72 74 61 6e 74 20 64 69 73 70 6c 61 79 20 64 72 69 76 65 72 20 75 70 64 61 74 65 20 28 44 6f 6e 20 6e 6f 74 20 64 65 6c 65 74 65 29 } //1 Important display driver update (Don not delete)
		$a_01_3 = {73 65 72 76 65 72 31 } //2 server1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2) >=5
 
}