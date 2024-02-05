
rule Trojan_Win32_Daonol_A{
	meta:
		description = "Trojan:Win32/Daonol.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 c0 35 50 e8 90 01 02 ff ff 8b 44 24 10 8b 54 24 08 c6 44 10 35 2b 6a 0a e8 90 00 } //01 00 
		$a_01_1 = {68 45 01 00 00 8b 44 24 1c 50 8b 44 24 18 50 e8 } //00 00 
	condition:
		any of ($a_*)
 
}