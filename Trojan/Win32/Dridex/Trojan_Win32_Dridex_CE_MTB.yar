
rule Trojan_Win32_Dridex_CE_MTB{
	meta:
		description = "Trojan:Win32/Dridex.CE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_81_0 = {31 43 68 72 6f 6d 65 2c 61 58 4d 73 75 63 68 6d 51 } //03 00 
		$a_81_1 = {47 6f 6f 67 6c 65 61 6e 64 33 6d } //03 00 
		$a_81_2 = {61 74 68 65 6b 54 5a 58 } //03 00 
		$a_81_3 = {71 6f 65 6e 77 6f 69 64 65 72 64 2e 64 6c 6c } //03 00 
		$a_81_4 = {44 66 6f 65 72 46 6f 70 71 77 64 66 72 73 } //03 00 
		$a_81_5 = {6b 65 72 6e 65 6c 33 32 2e 53 6c 65 65 70 } //03 00 
		$a_81_6 = {52 46 46 47 54 45 51 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Dridex_CE_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.CE!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {83 c0 01 83 c0 02 83 e8 02 cc 83 c0 02 83 e8 02 cc 83 c0 02 83 e8 02 cc 83 c0 02 83 c0 02 83 e8 02 83 e8 02 cc 83 c0 02 83 e8 02 } //00 00 
	condition:
		any of ($a_*)
 
}