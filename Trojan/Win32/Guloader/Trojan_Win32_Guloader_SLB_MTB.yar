
rule Trojan_Win32_Guloader_SLB_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SLB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {49 73 62 72 79 64 65 6e 64 65 2e 61 66 72 } //1 Isbrydende.afr
		$a_81_1 = {43 72 79 73 74 61 6c 69 7a 65 72 2e 53 79 6e } //1 Crystalizer.Syn
		$a_81_2 = {6d 65 74 61 62 61 73 69 73 2e 73 74 65 } //1 metabasis.ste
		$a_81_3 = {70 6c 61 73 6d 6f 6c 79 7a 61 62 6c 65 2e 64 65 6d } //1 plasmolyzable.dem
		$a_81_4 = {76 69 6e 64 73 70 69 6c 6c 65 72 2e 63 79 73 } //1 vindspiller.cys
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}
rule Trojan_Win32_Guloader_SLB_MTB_2{
	meta:
		description = "Trojan:Win32/Guloader.SLB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {74 69 6c 73 6c 75 74 6e 69 6e 67 73 74 6f 67 65 73 20 76 69 67 74 65 6e 64 65 20 65 6e 74 75 73 69 61 73 74 } //1 tilslutningstoges vigtende entusiast
		$a_81_1 = {74 69 6c 64 6e 67 65 64 65 20 65 6e 74 6f 6d 6f 74 6f 6d 69 73 74 20 74 72 69 6e 73 6b 69 66 74 65 72 6e 65 } //1 tildngede entomotomist trinskifterne
		$a_81_2 = {6d 75 6c 74 69 66 69 6c 65 72 20 73 68 65 6e 64 66 75 6c 2e 65 78 65 } //1 multifiler shendful.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}