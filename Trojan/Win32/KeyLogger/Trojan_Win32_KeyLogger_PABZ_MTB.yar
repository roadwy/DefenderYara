
rule Trojan_Win32_KeyLogger_PABZ_MTB{
	meta:
		description = "Trojan:Win32/KeyLogger.PABZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 6f 74 20 73 74 61 72 74 65 64 } //01 00  Bot started
		$a_01_1 = {56 69 72 75 73 } //01 00  Virus
		$a_01_2 = {23 73 70 61 6d } //01 00  #spam
		$a_01_3 = {4b 4f 53 4f 4d 41 4b 59 34 44 } //01 00  KOSOMAKY4D
		$a_01_4 = {56 72 58 2d 20 42 6f 74 20 49 44 3a 20 25 73 } //00 00  VrX- Bot ID: %s
	condition:
		any of ($a_*)
 
}