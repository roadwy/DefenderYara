
rule Trojan_Win32_Zenpak_GTM_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GTM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {65 30 58 4d 6f 76 69 6e 67 73 69 78 74 68 74 68 65 35 64 } //e0XMovingsixththe5d  1
		$a_80_1 = {58 32 66 69 72 6d 61 6d 65 6e 74 47 66 6c 79 75 73 39 } //X2firmamentGflyus9  1
		$a_80_2 = {6e 73 70 69 72 69 74 6b 43 61 74 74 6c 65 76 48 67 61 74 68 65 72 69 6e 67 } //nspiritkCattlevHgathering  1
		$a_80_3 = {74 72 65 65 6c 61 6e 64 66 69 73 68 6d 43 61 74 74 6c 65 57 65 72 65 } //treelandfishmCattleWere  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}