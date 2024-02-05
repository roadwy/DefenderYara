
rule Trojan_Win32_PSWStealer_GTQ_MTB{
	meta:
		description = "Trojan:Win32/PSWStealer.GTQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {c6 40 04 01 cc e9 00 00 00 00 33 c0 33 c0 0f 84 00 00 00 00 85 ff 83 e9 20 85 c9 c1 e0 10 0f 85 41 02 00 00 c2 08 00 } //01 00 
		$a_01_1 = {2e 6c 6f 61 74 68 6c 69 } //01 00 
		$a_01_2 = {2e 6c 69 67 61 6d 65 6e } //01 00 
		$a_01_3 = {47 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //00 00 
	condition:
		any of ($a_*)
 
}