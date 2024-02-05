
rule TrojanDropper_Win32_Lamberts_AS_MTB{
	meta:
		description = "TrojanDropper:Win32/Lamberts.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 4c 24 04 8b 01 69 c0 90 01 04 05 39 30 00 00 89 01 c1 e8 10 25 90 00 } //01 00 
		$a_00_1 = {32 04 3a 59 88 06 46 42 80 7d 10 00 } //00 00 
	condition:
		any of ($a_*)
 
}