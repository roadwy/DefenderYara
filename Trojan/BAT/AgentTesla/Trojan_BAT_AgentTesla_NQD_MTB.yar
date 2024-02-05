
rule Trojan_BAT_AgentTesla_NQD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NQD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_80_0 = {31 39 30 2e 31 32 33 2e 34 34 2e 31 33 38 2f 6c 6f 61 64 65 72 2f 75 70 6c 6f 61 64 73 2f } //190.123.44.138/loader/uploads/  01 00 
		$a_80_1 = {2d 65 6e 63 20 55 77 42 30 41 47 45 41 63 67 42 30 41 43 30 41 55 77 42 73 41 47 55 41 5a 51 42 77 41 43 } //-enc UwB0AGEAcgB0AC0AUwBsAGUAZQBwAC  01 00 
		$a_80_2 = {70 6f 77 65 72 73 68 65 6c 6c } //powershell  01 00 
		$a_01_3 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}