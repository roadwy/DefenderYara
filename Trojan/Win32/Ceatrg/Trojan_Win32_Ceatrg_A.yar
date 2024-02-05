
rule Trojan_Win32_Ceatrg_A{
	meta:
		description = "Trojan:Win32/Ceatrg.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 46 7c 00 ff ff ff ff 06 00 00 00 46 6c 6f 6f 64 5b 00 } //01 00 
		$a_03_1 = {6a 00 68 01 20 00 00 56 8b 43 04 50 e8 90 01 04 85 c0 7e 03 40 75 90 01 01 8b 43 04 50 e8 90 01 04 68 88 13 00 00 e8 90 01 04 e9 90 01 02 ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}