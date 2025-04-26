
rule Trojan_BAT_NjRat_NEDD_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_01_0 = {66 38 30 36 30 62 36 61 2d 65 33 66 61 2d 34 35 38 32 2d 61 64 31 66 2d 37 38 33 39 31 64 30 62 61 61 37 37 } //5 f8060b6a-e3fa-4582-ad1f-78391d0baa77
		$a_01_1 = {58 49 49 49 20 43 4f 4d 4d 55 4e 49 54 59 } //2 XIII COMMUNITY
		$a_01_2 = {56 69 67 65 6e 65 72 65 44 65 63 72 79 70 74 } //2 VigenereDecrypt
		$a_01_3 = {67 65 74 5f 45 6e 74 72 79 50 6f 69 6e 74 } //1 get_EntryPoint
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=10
 
}