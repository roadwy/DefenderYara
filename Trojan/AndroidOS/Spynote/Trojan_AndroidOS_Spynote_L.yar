
rule Trojan_AndroidOS_Spynote_L{
	meta:
		description = "Trojan:AndroidOS/Spynote.L,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {4c 63 6d 66 30 2f 63 33 62 35 62 6d 39 30 7a 71 2f 70 61 74 63 68 2f } //2 Lcmf0/c3b5bm90zq/patch/
		$a_00_1 = {4c 63 6f 6d 2f 61 6e 64 72 6f 69 64 2f 74 65 73 74 65 72 2f } //2 Lcom/android/tester/
		$a_01_2 = {43 41 4d 43 4f 52 44 45 52 } //1 CAMCORDER
		$a_00_3 = {2f 53 63 72 65 65 6e 73 68 6f 74 73 } //1 /Screenshots
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}