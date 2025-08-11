
rule Trojan_BAT_Jalapeno_DB_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,6a 00 6a 00 07 00 00 "
		
	strings :
		$a_81_0 = {4f 6b 71 69 63 7a 79 69 63 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //100 Okqiczyic.Properties.Resources
		$a_81_1 = {53 68 72 62 6c 63 } //1 Shrblc
		$a_81_2 = {41 79 76 69 67 76 65 72 } //1 Ayvigver
		$a_81_3 = {4f 61 6c 67 6c 78 75 76 78 6b 74 } //1 Oalglxuvxkt
		$a_81_4 = {42 74 66 7a 64 77 75 71 77 } //1 Btfzdwuqw
		$a_81_5 = {77 33 77 70 2e 65 78 65 } //1 w3wp.exe
		$a_81_6 = {61 73 70 6e 65 74 5f 77 70 2e 65 78 65 } //1 aspnet_wp.exe
	condition:
		((#a_81_0  & 1)*100+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=106
 
}