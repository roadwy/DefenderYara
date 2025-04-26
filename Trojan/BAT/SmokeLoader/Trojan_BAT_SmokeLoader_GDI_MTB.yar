
rule Trojan_BAT_SmokeLoader_GDI_MTB{
	meta:
		description = "Trojan:BAT/SmokeLoader.GDI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {69 63 63 6f 70 65 72 61 64 6f 72 61 2e 63 6f 6d 2e 62 72 2f 65 72 72 6f 73 5f 4f 4c 44 } //iccoperadora.com.br/erros_OLD  1
		$a_01_1 = {6d 38 44 41 46 37 36 32 38 45 31 37 43 36 38 35 } //1 m8DAF7628E17C685
		$a_01_2 = {66 38 44 41 46 37 36 32 38 45 31 37 41 44 41 35 } //1 f8DAF7628E17ADA5
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_4 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
	condition:
		((#a_80_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}