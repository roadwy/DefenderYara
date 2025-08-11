
rule Trojan_Win32_Guloader_GPC_MTB{
	meta:
		description = "Trojan:Win32/Guloader.GPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {6c 65 61 72 79 } //1 leary
		$a_81_1 = {66 69 6e 70 75 64 73 65 6e 64 65 73 } //1 finpudsendes
		$a_81_2 = {6c 61 67 65 72 70 6c 61 64 73 62 65 68 6f 76 65 6e 65 73 20 75 6d 65 64 67 72 6c 69 67 } //1 lagerpladsbehovenes umedgrlig
		$a_81_3 = {61 6d 65 62 61 20 70 6c 75 6d 70 73 20 68 69 6e 61 6e 64 65 6e 73 } //1 ameba plumps hinandens
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}