
rule Trojan_Win32_Gandcrab_JRL_MTB{
	meta:
		description = "Trojan:Win32/Gandcrab.JRL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {30 04 1e 46 3b f7 7c 90 0a 12 00 e8 90 01 03 00 90 00 } //01 00 
		$a_02_1 = {00 33 c5 89 45 90 01 01 69 05 90 01 03 00 90 01 04 05 90 01 04 a3 90 0a 28 00 a1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}