
rule Trojan_Win32_Emotet_DFR_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DFR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 cb 03 c1 99 b9 90 01 04 f7 f9 8b 4c 24 18 8b 84 24 90 01 04 8a 1c 01 8a 54 14 1c 32 da 88 1c 01 90 00 } //01 00 
		$a_81_1 = {46 46 67 58 59 5a 69 56 52 31 59 64 72 56 4c 6f 57 45 6e 78 71 56 42 68 53 34 77 48 34 55 67 51 4b 55 58 } //00 00  FFgXYZiVR1YdrVLoWEnxqVBhS4wH4UgQKUX
	condition:
		any of ($a_*)
 
}