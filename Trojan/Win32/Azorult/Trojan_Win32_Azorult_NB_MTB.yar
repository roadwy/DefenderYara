
rule Trojan_Win32_Azorult_NB_MTB{
	meta:
		description = "Trojan:Win32/Azorult.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {47 3b 7d 08 90 18 e8 90 02 04 30 90 02 02 83 90 02 03 75 90 00 } //01 00 
		$a_02_1 = {47 3b 7d 08 90 18 90 18 a1 90 02 04 69 90 02 05 81 90 02 09 a3 90 02 04 90 18 81 90 02 09 0f 90 02 06 25 90 02 04 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}