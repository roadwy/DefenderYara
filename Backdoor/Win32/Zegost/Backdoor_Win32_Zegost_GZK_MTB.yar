
rule Backdoor_Win32_Zegost_GZK_MTB{
	meta:
		description = "Backdoor:Win32/Zegost.GZK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 76 63 68 73 6f 74 2e 65 78 65 } //01 00 
		$a_01_1 = {68 61 6e 61 62 65 6e 6b 2e 63 6f 6d } //01 00 
		$a_01_2 = {65 70 6f 73 74 62 65 6e 6b 2e 67 6f } //01 00 
		$a_01_3 = {54 47 39 6a 59 57 78 54 61 58 70 6c } //01 00 
		$a_01_4 = {52 32 56 30 52 45 6c 43 61 58 52 7a } //00 00 
	condition:
		any of ($a_*)
 
}