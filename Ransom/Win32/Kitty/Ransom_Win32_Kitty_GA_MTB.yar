
rule Ransom_Win32_Kitty_GA_MTB{
	meta:
		description = "Ransom:Win32/Kitty.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_80_0 = {48 65 6c 6c 6f 4b 69 74 74 79 4d 75 74 65 78 } //HelloKittyMutex  01 00 
		$a_80_1 = {64 65 63 72 79 70 74 } //decrypt  01 00 
		$a_80_2 = {2e 6f 6e 69 6f 6e } //.onion  01 00 
		$a_80_3 = {20 70 61 79 20 } // pay   01 00 
		$a_80_4 = {53 68 61 64 6f 77 43 6f 70 79 } //ShadowCopy  00 00 
	condition:
		any of ($a_*)
 
}