
rule Trojan_Win32_Qakbot_HA_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.HA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {77 68 6e 6d 31 30 39 72 6f 30 38 2e 64 6c 6c } //01 00 
		$a_01_1 = {44 72 61 77 54 68 65 6d 65 49 63 6f 6e } //01 00 
		$a_01_2 = {52 59 4a 64 77 38 34 35 35 64 7a 53 } //01 00 
		$a_01_3 = {46 64 46 41 39 42 37 4e } //01 00 
		$a_01_4 = {5a 67 59 54 30 74 34 69 } //01 00 
		$a_01_5 = {43 77 6d 55 63 67 38 36 } //01 00 
		$a_01_6 = {43 62 4e 42 30 } //00 00 
	condition:
		any of ($a_*)
 
}