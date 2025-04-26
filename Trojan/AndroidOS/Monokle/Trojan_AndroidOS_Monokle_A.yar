
rule Trojan_AndroidOS_Monokle_A{
	meta:
		description = "Trojan:AndroidOS/Monokle.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {72 65 63 73 32 33 33 32 36 38 } //1 recs233268
		$a_00_1 = {6e 73 72 33 39 35 36 32 32 36 37 2e 6c 6d 74 } //1 nsr39562267.lmt
		$a_00_2 = {41 6e 64 72 6f 69 64 2f 64 61 74 61 2f 73 65 72 76 38 32 30 32 39 36 35 } //1 Android/data/serv8202965
		$a_00_3 = {6c 63 64 31 31 30 39 39 32 32 36 34 2e 64 } //1 lcd110992264.d
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}