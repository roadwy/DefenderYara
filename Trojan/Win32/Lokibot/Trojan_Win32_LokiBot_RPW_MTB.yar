
rule Trojan_Win32_LokiBot_RPW_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.RPW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 65 73 6f 63 69 61 6c 69 73 65 72 69 6e 67 65 72 6e 65 73 31 } //01 00  resocialiseringernes1
		$a_01_1 = {46 6f 72 62 69 67 61 61 65 6c 73 65 31 } //01 00  Forbigaaelse1
		$a_01_2 = {46 49 4b 53 45 52 45 4e 44 45 53 31 } //01 00  FIKSERENDES1
		$a_01_3 = {53 74 69 66 74 6d 6f 73 61 69 6b 67 75 6c 76 65 74 73 31 } //01 00  Stiftmosaikgulvets1
		$a_01_4 = {53 6b 6f 76 76 73 65 6e 65 74 40 52 45 56 4f 59 41 47 45 2e 73 74 69 30 } //00 00  Skovvsenet@REVOYAGE.sti0
	condition:
		any of ($a_*)
 
}