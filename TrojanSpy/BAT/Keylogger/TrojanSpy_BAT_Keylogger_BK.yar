
rule TrojanSpy_BAT_Keylogger_BK{
	meta:
		description = "TrojanSpy:BAT/Keylogger.BK,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {74 61 7a 6e 61 63 74 30 30 32 40 67 6d 61 69 6c 2e 63 6f 6d } //taznact002@gmail.com  1
		$a_80_1 = {72 71 62 67 76 6e 66 6d 70 71 6b 77 61 6d 62 77 } //rqbgvnfmpqkwambw  1
		$a_80_2 = {62 73 73 5f 63 68 72 6f 6d } //bss_chrom  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}