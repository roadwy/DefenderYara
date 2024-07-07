
rule Trojan_Win64_CashStream_ZZ{
	meta:
		description = "Trojan:Win64/CashStream.ZZ,SIGNATURE_TYPE_PEHSTR_EXT,ffffffdd 00 ffffffdd 00 05 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_01_1 = {41 0f b6 02 4d 8d 52 01 44 33 c8 41 8b c1 d1 e8 8b c8 81 f1 78 3b f6 82 41 80 e1 01 0f 44 c8 8b c1 d1 e8 8b d0 81 f2 78 3b f6 82 80 e1 01 0f 44 d0 } //100
		$a_81_2 = {30 30 31 34 62 72 2e 67 6f 76 2e 62 63 62 2e 70 69 78 } //100 0014br.gov.bcb.pix
		$a_81_3 = {63 62 4d 6f 6e 69 74 6f 72 } //10 cbMonitor
		$a_81_4 = {74 63 70 3a 2f 2f 31 32 37 2e 30 2e 30 2e 31 3a 25 68 75 } //10 tcp://127.0.0.1:%hu
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*100+(#a_81_2  & 1)*100+(#a_81_3  & 1)*10+(#a_81_4  & 1)*10) >=221
 
}