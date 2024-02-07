
rule Trojan_Win32_Aujil_A{
	meta:
		description = "Trojan:Win32/Aujil.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 61 75 74 6f 72 75 6e 2e 69 6e 66 } //01 00  \autorun.inf
		$a_01_1 = {33 ff 81 7d 1c 07 20 01 00 } //01 00 
		$a_01_2 = {a5 6a 0f 66 a5 53 6a ff a4 } //00 00 
	condition:
		any of ($a_*)
 
}