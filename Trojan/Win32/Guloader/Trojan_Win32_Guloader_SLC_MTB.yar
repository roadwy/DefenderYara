
rule Trojan_Win32_Guloader_SLC_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SLC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {64 69 73 63 6f 75 72 74 65 6f 75 73 6c 79 2e 67 61 6d } //1 discourteously.gam
		$a_81_1 = {70 73 79 63 68 6f 67 72 61 70 68 2e 72 75 74 } //1 psychograph.rut
		$a_81_2 = {73 74 72 75 64 73 66 6a 65 72 65 6e 65 73 2e 75 6e 73 } //1 strudsfjerenes.uns
		$a_81_3 = {65 6c 69 61 20 67 65 6f 6d 6f 72 66 6f 6c 6f 67 69 } //1 elia geomorfologi
		$a_81_4 = {69 6c 6c 75 73 74 72 61 74 6f 72 20 6f 62 73 74 69 6e 61 74 65 6e 65 73 73 20 6e 6f 6e 66 65 61 6c 74 69 65 73 } //1 illustrator obstinateness nonfealties
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}