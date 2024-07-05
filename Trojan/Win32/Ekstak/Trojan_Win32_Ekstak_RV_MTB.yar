
rule Trojan_Win32_Ekstak_RV_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.RV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 05 00 "
		
	strings :
		$a_03_0 = {55 8b ec 51 56 68 90 01 01 df 64 00 e8 01 74 fb ff e9 90 00 } //05 00 
		$a_01_1 = {55 8b ec 51 56 68 1f df 64 00 e8 f1 73 fb ff e9 } //02 00 
		$a_01_2 = {40 00 00 40 5f 6c 69 62 73 74 64 } //02 00 
		$a_01_3 = {40 00 00 40 2e 6c 69 62 73 74 64 } //01 00 
		$a_01_4 = {43 00 6f 00 76 00 65 00 72 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //00 00  CoverCommander.exe
	condition:
		any of ($a_*)
 
}