
rule Trojan_Win32_Cridex_RM_MTB{
	meta:
		description = "Trojan:Win32/Cridex.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_81_0 = {33 64 6f 43 68 72 6f 6d 65 73 64 61 79 73 2e 31 39 37 74 79 70 65 73 } //01 00  3doChromesdays.197types
		$a_81_1 = {43 68 72 6f 6d 65 73 6f 6c 76 69 6e 67 2e 31 32 33 77 68 69 63 68 6d } //01 00  Chromesolving.123whichm
		$a_81_2 = {59 6f 75 6f 6e 66 65 61 74 75 72 65 73 63 6f 6e 6e 65 63 74 69 6f 6e 62 72 6f 77 73 65 72 73 2e 36 32 67 6f 6e 6c 79 54 68 65 4a 5a } //00 00  Youonfeaturesconnectionbrowsers.62gonlyTheJZ
	condition:
		any of ($a_*)
 
}