
rule Trojan_Win32_Convagent_DX_MTB{
	meta:
		description = "Trojan:Win32/Convagent.DX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 03 00 "
		
	strings :
		$a_03_0 = {50 8d 45 fc 50 8b 45 fc 8d 04 86 50 56 57 e8 90 02 04 8b 45 fc 83 c4 14 48 89 35 a8 bc 45 01 5f 5e a3 a4 bc 45 01 5b c9 90 00 } //01 00 
		$a_01_1 = {53 00 74 00 65 00 61 00 6d 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 2e 00 65 00 78 00 65 00 } //01 00  SteamService.exe
		$a_01_2 = {2e 69 38 31 34 } //01 00  .i814
		$a_01_3 = {2e 69 38 31 35 } //01 00  .i815
		$a_01_4 = {2e 69 38 31 36 } //00 00  .i816
	condition:
		any of ($a_*)
 
}