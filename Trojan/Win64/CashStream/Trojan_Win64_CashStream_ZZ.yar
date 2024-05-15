
rule Trojan_Win64_CashStream_ZZ{
	meta:
		description = "Trojan:Win64/CashStream.ZZ,SIGNATURE_TYPE_PEHSTR_EXT,ffffffdd 00 ffffffdd 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //64 00 
		$a_01_1 = {41 0f b6 02 4d 8d 52 01 44 33 c8 41 8b c1 d1 e8 8b c8 81 f1 78 3b f6 82 41 80 e1 01 0f 44 c8 8b c1 d1 e8 8b d0 81 f2 78 3b f6 82 80 e1 01 0f 44 d0 } //64 00 
		$a_81_2 = {30 30 31 34 62 72 2e 67 6f 76 2e 62 63 62 2e 70 69 78 } //0a 00  0014br.gov.bcb.pix
		$a_81_3 = {63 62 4d 6f 6e 69 74 6f 72 } //0a 00  cbMonitor
		$a_81_4 = {74 63 70 3a 2f 2f 31 32 37 2e 30 2e 30 2e 31 3a 25 68 75 } //00 00  tcp://127.0.0.1:%hu
		$a_00_5 = {5d 04 00 00 d2 70 06 80 5c 34 00 00 d3 70 06 80 00 00 01 00 08 00 1e 00 54 72 6f 6a 61 6e 3a 57 69 6e 36 34 2f 43 61 73 68 53 74 72 65 61 6d 2e 5a 5a 21 73 6d 73 00 00 01 40 05 82 70 00 04 00 ce 09 00 00 7a dd 64 af 78 8b 00 00 7b 5d 04 00 00 d3 70 06 80 5c 3c 00 00 d4 70 06 80 00 00 01 00 08 00 26 00 54 72 6f 6a 61 6e 3a 50 6f 77 65 72 53 68 65 6c 6c 2f 4f 62 66 75 73 63 61 74 65 64 50 6f 77 65 72 53 68 65 6c 6c 00 00 03 40 05 82 70 00 04 00 7a 08 00 00 31 00 00 00 01 00 00 00 e7 6e 00 00 00 00 6a 00 ad e6 17 d1 67 ac 1a 80 0b c7 18 80 ea ea e3 ad c7 17 c7 31 bc 3f 8f 12 c7 05 67 0f ec fc d0 31 ea da d1 f2 ac 3f ec e3 ad c7 17 8f c7 05 67 0f ec 6a 99 } //c3 da 
	condition:
		any of ($a_*)
 
}