
rule Trojan_Win32_PswStealer_AA_MTB{
	meta:
		description = "Trojan:Win32/PswStealer.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 53 74 65 61 6c 65 72 5f 46 69 6c 65 5a 69 6c 6c 61 } //01 00 
		$a_01_1 = {53 74 65 61 6c 65 72 5f 54 6f 74 61 6c 43 6d 64 } //01 00 
		$a_01_2 = {53 65 72 76 65 72 5c 50 61 73 73 77 6f 72 64 56 69 65 77 4f 6e 6c 79 } //00 00 
	condition:
		any of ($a_*)
 
}