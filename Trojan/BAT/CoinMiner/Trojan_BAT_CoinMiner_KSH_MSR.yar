
rule Trojan_BAT_CoinMiner_KSH_MSR{
	meta:
		description = "Trojan:BAT/CoinMiner.KSH!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {76 00 69 00 68 00 61 00 6e 00 73 00 6f 00 66 00 74 00 2e 00 69 00 72 00 } //01 00  vihansoft.ir
		$a_01_1 = {53 00 79 00 73 00 74 00 65 00 6d 00 4d 00 61 00 6e 00 61 00 67 00 65 00 6d 00 65 00 6e 00 74 00 2e 00 65 00 78 00 65 00 } //01 00  SystemManagement.exe
		$a_00_2 = {57 69 6e 64 6f 77 73 53 65 63 75 72 69 74 79 53 65 72 76 69 63 65 2e 70 64 62 } //01 00  WindowsSecurityService.pdb
		$a_01_3 = {63 00 6f 00 6e 00 66 00 69 00 67 00 2e 00 6a 00 73 00 6f 00 6e 00 } //00 00  config.json
	condition:
		any of ($a_*)
 
}