
rule Trojan_BAT_DCRat_RDC_MTB{
	meta:
		description = "Trojan:BAT/DCRat.RDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {31 38 42 57 70 37 35 36 74 61 49 63 54 68 66 36 50 70 70 74 57 30 34 41 79 43 61 45 59 45 6b 64 39 72 73 6a 51 62 58 49 61 73 66 42 } //1 18BWp756taIcThf6PpptW04AyCaEYEkd9rsjQbXIasfB
		$a_01_1 = {49 54 74 48 77 63 42 50 73 55 35 5a 62 58 47 6d 6c 61 } //1 ITtHwcBPsU5ZbXGmla
		$a_01_2 = {37 70 42 48 46 74 43 70 6c 36 51 69 6d 34 49 75 58 6f } //1 7pBHFtCpl6Qim4IuXo
		$a_01_3 = {6c 53 66 67 41 70 61 74 6b 64 78 73 56 63 47 63 72 6b 74 6f 46 64 } //1 lSfgApatkdxsVcGcrktoFd
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}