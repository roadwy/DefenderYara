
rule Trojan_BAT_Stealer_MVE_MTB{
	meta:
		description = "Trojan:BAT/Stealer.MVE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_80_0 = {49 4e 5a 53 74 65 61 6c 65 72 2e 65 78 65 } //INZStealer.exe  01 00 
		$a_80_1 = {50 61 73 73 77 6f 72 64 73 } //Passwords  01 00 
		$a_80_2 = {44 69 73 63 6f 72 64 } //Discord  01 00 
		$a_80_3 = {4c 6f 67 69 6e 20 44 61 74 61 } //Login Data  00 00 
	condition:
		any of ($a_*)
 
}