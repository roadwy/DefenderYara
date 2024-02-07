
rule Trojan_BAT_Bladabindi_NEG_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.NEG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 72 01 00 00 70 6f 04 00 00 0a 0a de 0a 07 2c 06 07 6f 05 00 00 0a dc 28 06 00 00 0a 72 90 01 01 00 00 70 28 07 00 00 0a 06 28 08 00 00 0a 20 b0 04 00 00 28 09 00 00 0a 28 06 00 00 0a 72 90 01 01 00 00 70 28 07 00 00 0a 28 0a 00 00 0a 26 7e 0b 00 00 0a 26 de 03 90 00 } //01 00 
		$a_01_1 = {68 00 65 00 61 00 6c 00 74 00 68 00 70 00 79 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 2e 00 63 00 6f 00 6d 00 } //01 00  healthpyservices.com
		$a_01_2 = {52 00 65 00 67 00 41 00 73 00 6d 00 2e 00 65 00 78 00 65 00 } //00 00  RegAsm.exe
	condition:
		any of ($a_*)
 
}