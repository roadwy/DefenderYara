
rule Trojan_BAT_Nekark_MTB{
	meta:
		description = "Trojan:BAT/Nekark!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {4d 69 63 72 6f 73 6f 66 74 2e 65 78 65 } //3 Microsoft.exe
		$a_80_1 = {54 57 6c 6a 63 6d 39 7a 62 32 5a 30 4a 51 3d 3d } //TWljcm9zb2Z0JQ==  1
		$a_80_2 = {54 57 6c 6a 63 6d 39 7a 62 32 5a 30 4a 41 3d 3d } //TWljcm9zb2Z0JA==  1
		$a_80_3 = {54 57 6c 6a 63 6d 39 7a 62 32 5a 30 4b 67 3d 3d } //TWljcm9zb2Z0Kg==  1
	condition:
		((#a_00_0  & 1)*3+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}