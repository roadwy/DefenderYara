
rule Trojan_BAT_AveMaria_NET_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NET!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {59 66 65 66 66 65 65 66 65 66 65 66 } //3 Yfeffeefefef
		$a_01_1 = {67 65 74 5f 50 65 61 63 68 50 75 66 66 } //3 get_PeachPuff
		$a_01_2 = {54 6f 72 74 79 31 2e 50 72 6f 70 65 72 74 69 65 73 } //3 Torty1.Properties
		$a_01_3 = {32 53 79 73 74 65 6d 2e 43 6f 6c 6c 65 63 74 69 6f 6e 73 2e 43 61 73 65 49 6e 73 65 6e 73 69 74 69 76 65 48 61 73 68 43 6f 64 65 50 72 6f 76 69 64 65 72 } //2 2System.Collections.CaseInsensitiveHashCodeProvider
		$a_01_4 = {4d 61 6e 61 67 65 6d 65 6e 74 20 41 73 73 69 73 74 61 6e 74 } //2 Management Assistant
		$a_01_5 = {43 6f 6d 70 6c 65 74 65 20 54 65 63 68 } //2 Complete Tech
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=15
 
}