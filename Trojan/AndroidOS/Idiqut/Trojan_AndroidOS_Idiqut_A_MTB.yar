
rule Trojan_AndroidOS_Idiqut_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Idiqut.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {61 70 70 5f 73 69 6b 68 79 77 69 73 5f 63 61 35 35 32 30 30 65 } //1 app_sikhywis_ca55200e
		$a_01_1 = {63 6f 6d 2e 73 65 63 2e 77 68 69 73 6b 79 2e 53 63 6f 74 63 68 } //1 com.sec.whisky.Scotch
		$a_01_2 = {2f 73 63 6f 74 63 68 2e 6a 61 72 } //1 /scotch.jar
		$a_01_3 = {62 69 6e 32 6d 64 35 } //1 bin2md5
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}