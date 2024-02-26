
rule Trojan_BAT_Ogoxts_MA_MTB{
	meta:
		description = "Trojan:BAT/Ogoxts.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {07 08 06 08 9a 1f 10 28 53 00 00 0a 9c 08 17 58 0c 08 06 8e 69 32 e9 07 2a } //01 00 
		$a_01_1 = {44 4c 4c 5f 50 52 4f 43 45 53 53 5f 41 54 54 41 43 48 } //00 00  DLL_PROCESS_ATTACH
	condition:
		any of ($a_*)
 
}