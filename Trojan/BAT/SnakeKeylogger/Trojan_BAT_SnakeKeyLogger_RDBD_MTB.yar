
rule Trojan_BAT_SnakeKeyLogger_RDBD_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDBD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 61 6d 74 61 73 69 61 20 53 74 75 64 69 6f } //1 Camtasia Studio
		$a_01_1 = {54 65 63 68 53 6d 69 74 68 20 43 6f 72 70 6f 72 61 74 69 6f 6e } //1 TechSmith Corporation
		$a_01_2 = {53 65 61 72 63 68 43 75 73 74 6f 6d 65 72 } //2 SearchCustomer
		$a_01_3 = {50 6f 73 74 43 75 73 74 6f 6d 65 72 } //2 PostCustomer
		$a_01_4 = {4d 61 6e 61 67 65 43 75 73 74 6f 6d 65 72 } //2 ManageCustomer
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=8
 
}