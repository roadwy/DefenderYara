
rule Trojan_Win32_Emotet_DEY_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DEY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 c1 0f b6 4d 90 01 01 89 45 90 01 01 8b 45 f0 0f b6 84 05 90 01 04 03 c1 8b cb 99 f7 f9 8b 45 90 1b 01 8a 8c 15 90 1b 02 30 08 90 00 } //01 00 
		$a_81_1 = {33 6d 32 6c 79 35 30 39 58 47 65 64 71 43 71 68 43 6a 59 6d 72 72 49 51 44 73 } //00 00  3m2ly509XGedqCqhCjYmrrIQDs
	condition:
		any of ($a_*)
 
}