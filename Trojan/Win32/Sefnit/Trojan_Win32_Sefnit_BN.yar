
rule Trojan_Win32_Sefnit_BN{
	meta:
		description = "Trojan:Win32/Sefnit.BN,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 86 b0 00 00 00 2b 86 e4 00 00 00 2b 86 ac 00 00 00 03 86 e8 00 00 00 50 } //01 00 
		$a_01_1 = {89 51 44 8b 40 04 89 41 48 8d 41 28 83 ec 10 83 78 14 10 72 02 8b 00 } //00 00 
	condition:
		any of ($a_*)
 
}