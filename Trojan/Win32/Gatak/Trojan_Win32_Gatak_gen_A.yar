
rule Trojan_Win32_Gatak_gen_A{
	meta:
		description = "Trojan:Win32/Gatak.gen!A,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {76 65 76 65 72 6b 61 2e 6a 75 6e 79 6b 73 2e 63 7a 2f 72 65 70 6f 72 74 32 5f } //01 00  veverka.junyks.cz/report2_
		$a_01_1 = {76 65 76 65 72 6b 61 2e 6a 75 6e 79 6b 73 2e 63 7a 2f 72 65 70 6f 72 74 31 5f } //00 00  veverka.junyks.cz/report1_
	condition:
		any of ($a_*)
 
}