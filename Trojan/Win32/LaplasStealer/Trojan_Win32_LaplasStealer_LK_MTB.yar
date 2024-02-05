
rule Trojan_Win32_LaplasStealer_LK_MTB{
	meta:
		description = "Trojan:Win32/LaplasStealer.LK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {34 00 35 00 2e 00 31 00 35 00 39 00 2e 00 31 00 38 00 39 00 2e 00 31 00 30 00 35 00 } //01 00 
		$a_01_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 7b 00 30 00 7d 00 2f 00 62 00 6f 00 74 00 2f 00 7b 00 31 00 7d 00 3f 00 7b 00 32 00 7d 00 } //00 00 
	condition:
		any of ($a_*)
 
}