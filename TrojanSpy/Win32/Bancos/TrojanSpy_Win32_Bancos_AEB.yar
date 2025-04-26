
rule TrojanSpy_Win32_Bancos_AEB{
	meta:
		description = "TrojanSpy:Win32/Bancos.AEB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {74 6d 72 42 75 73 63 61 4d 53 4e 54 69 6d 65 72 } //1 tmrBuscaMSNTimer
		$a_01_1 = {62 6f 23 6f 6b 2e 74 61 23 6d 2e 63 6f 23 6d 2e 62 23 72 2f 70 23 6c } //1 bo#ok.ta#m.co#m.b#r/p#l
		$a_01_2 = {63 6f 23 6d 2e 62 23 72 2f 50 61 79 6d 23 65 6e 74 } //1 co#m.b#r/Paym#ent
		$a_01_3 = {43 4f 4e 54 52 23 4f 4c 47 52 4f 55 50 50 41 59 4d 45 4e 54 31 } //1 CONTR#OLGROUPPAYMENT1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}