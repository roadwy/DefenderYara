
rule Trojan_BAT_RedLine_RDBC_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 64 62 36 64 32 37 33 2d 63 36 39 39 2d 34 31 34 38 2d 61 34 38 65 2d 36 61 39 38 61 36 62 31 36 64 36 30 } //1 cdb6d273-c699-4148-a48e-6a98a6b16d60
		$a_01_1 = {4b 43 20 53 6f 66 74 77 61 72 65 73 } //1 KC Softwares
		$a_01_2 = {70 72 6f 66 65 73 73 69 6f 6e 61 6c 2d 73 65 74 75 70 5f 66 75 6c 6c } //1 professional-setup_full
		$a_01_3 = {4b 71 6d 75 61 53 48 54 55 4d 67 6b 44 4d 59 6e 45 71 63 69 4d 6a 69 4f 4a 74 43 51 2e 4a 51 76 70 49 74 57 4b 55 65 70 6c 6d 68 73 64 41 72 77 6c 48 74 62 6f 51 61 6c 48 } //1 KqmuaSHTUMgkDMYnEqciMjiOJtCQ.JQvpItWKUeplmhsdArwlHtboQalH
		$a_01_4 = {54 00 65 00 78 00 74 00 46 00 69 00 6c 00 65 00 31 00 } //1 TextFile1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}