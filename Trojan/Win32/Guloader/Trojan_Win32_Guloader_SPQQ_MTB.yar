
rule Trojan_Win32_Guloader_SPQQ_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SPQQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 00 65 00 74 00 61 00 6c 00 73 00 70 00 79 00 64 00 73 00 20 00 47 00 72 00 6f 00 76 00 65 00 72 00 } //01 00  metalspyds Grover
		$a_01_1 = {53 79 6d 62 6f 6c 6f 6c 6f 67 79 31 2a 30 28 } //01 00  Symbolology1*0(
		$a_01_2 = {53 65 61 73 6e 61 69 6c 40 4e 6f 6e 76 61 73 63 75 6c 61 72 6c 79 33 34 2e 42 69 31 25 30 23 } //01 00  Seasnail@Nonvascularly34.Bi1%0#
		$a_01_3 = {55 6e 69 64 69 72 65 63 74 69 6f 6e 20 4d 61 63 72 6f 61 67 67 72 65 67 61 74 65 20 31 } //01 00  Unidirection Macroaggregate 1
		$a_01_4 = {70 00 65 00 64 00 69 00 61 00 74 00 72 00 69 00 63 00 20 00 43 00 65 00 6d 00 65 00 6e 00 74 00 65 00 72 00 69 00 6e 00 67 00 65 00 6e 00 2e 00 65 00 78 00 65 00 } //00 00  pediatric Cementeringen.exe
	condition:
		any of ($a_*)
 
}