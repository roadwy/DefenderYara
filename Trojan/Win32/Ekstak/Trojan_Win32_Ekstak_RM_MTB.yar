
rule Trojan_Win32_Ekstak_RM_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {56 68 01 ef 64 00 e8 05 72 fb ff 8b f0 e9 } //01 00 
		$a_01_1 = {56 68 31 ef 64 00 e8 85 71 fb ff 8b f0 e9 } //01 00 
		$a_01_2 = {56 68 21 ef 64 00 e8 85 71 fb ff 8b f0 e9 } //00 00 
	condition:
		any of ($a_*)
 
}