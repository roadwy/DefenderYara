
rule Trojan_Win32_Pterodactyl_SPL_MTB{
	meta:
		description = "Trojan:Win32/Pterodactyl.SPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {46 65 72 66 79 47 64 72 67 66 } //01 00 
		$a_81_1 = {41 64 66 67 68 4f 74 68 67 72 64 } //01 00 
		$a_81_2 = {4b 79 6a 74 68 72 67 4a 79 66 6a 74 } //01 00 
		$a_81_3 = {72 64 72 75 66 6e 69 74 75 2e 64 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}