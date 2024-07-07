
rule Trojan_BAT_AveMariaRat_ML_MTB{
	meta:
		description = "Trojan:BAT/AveMariaRat.ML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_01_1 = {74 00 69 00 6e 00 79 00 2e 00 6f 00 6e 00 65 00 2f 00 61 00 64 00 61 00 6d 00 30 00 32 00 30 00 34 00 35 00 64 00 61 00 6d 00 32 00 } //1 tiny.one/adam02045dam2
		$a_01_2 = {50 61 74 63 68 54 68 72 65 61 64 } //1 PatchThread
		$a_01_3 = {54 00 65 00 73 00 74 00 2d 00 43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 69 00 6f 00 6e 00 } //1 Test-Connection
		$a_01_4 = {52 70 70 74 67 64 63 6e 77 61 73 7a 6d 75 78 76 66 71 } //1 Rpptgdcnwaszmuxvfq
		$a_01_5 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}