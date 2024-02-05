
rule Trojan_Win32_Stealer_CD_MTB{
	meta:
		description = "Trojan:Win32/Stealer.CD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 fe 06 0c 00 00 75 05 e8 90 02 04 46 81 fe 35 6b 24 00 7c ea 90 00 } //01 00 
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00 
		$a_01_2 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00 
		$a_01_3 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 } //00 00 
	condition:
		any of ($a_*)
 
}