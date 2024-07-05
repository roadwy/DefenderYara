
rule Trojan_Win32_Ekstak_RU_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.RU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 05 00 "
		
	strings :
		$a_01_0 = {56 e8 fa 73 fb ff 8b f0 e9 } //05 00 
		$a_01_1 = {56 e8 3a 74 fb ff 8b f0 e9 } //05 00 
		$a_01_2 = {56 e8 0a 74 fb ff 8b f0 e9 } //05 00 
		$a_01_3 = {56 e8 1a 74 fb ff 8b f0 e9 } //02 00 
		$a_01_4 = {40 00 00 40 5f 6c 69 62 73 74 64 } //02 00 
		$a_01_5 = {40 00 00 40 2e 6c 69 62 73 74 64 } //01 00 
		$a_01_6 = {43 00 6f 00 76 00 65 00 72 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //00 00  CoverCommander.exe
	condition:
		any of ($a_*)
 
}