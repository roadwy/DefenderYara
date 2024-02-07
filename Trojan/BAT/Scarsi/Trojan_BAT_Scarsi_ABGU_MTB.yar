
rule Trojan_BAT_Scarsi_ABGU_MTB{
	meta:
		description = "Trojan:BAT/Scarsi.ABGU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {07 13 04 16 13 05 11 04 12 05 28 17 00 00 0a 06 09 28 0a 00 00 06 13 06 07 09 11 06 6f 18 00 00 0a de 0c 11 05 2c 07 11 04 28 19 00 00 0a dc 09 18 58 0d 09 06 6f 1a 00 00 0a 32 c4 } //01 00 
		$a_01_1 = {02 03 18 6f 1d 00 00 0a 1f 10 28 1e 00 00 0a 2a } //01 00 
		$a_01_2 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_01_3 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //01 00  GetResponseStream
		$a_01_4 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //00 00  InvokeMember
	condition:
		any of ($a_*)
 
}