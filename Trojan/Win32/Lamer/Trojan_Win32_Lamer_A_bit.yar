
rule Trojan_Win32_Lamer_A_bit{
	meta:
		description = "Trojan:Win32/Lamer.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 46 45 44 4f 54 5c 46 65 64 6f 74 2e 65 78 65 } //01 00 
		$a_01_1 = {43 3a 5c 53 65 72 76 69 63 65 5c 64 61 74 2e } //01 00 
		$a_01_2 = {58 58 2e 43 50 50 } //00 00 
	condition:
		any of ($a_*)
 
}