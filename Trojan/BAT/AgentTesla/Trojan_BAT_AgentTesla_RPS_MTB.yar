
rule Trojan_BAT_AgentTesla_RPS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RPS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 } //01 00  cdn.discordapp.com/attachments
		$a_01_1 = {52 00 6f 00 62 00 6c 00 6f 00 78 00 5f 00 45 00 72 00 72 00 6f 00 72 00 5f 00 46 00 69 00 78 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //01 00  Roblox_Error_Fixer.exe
		$a_01_2 = {44 00 65 00 6c 00 74 00 61 00 2e 00 65 00 78 00 65 00 } //01 00  Delta.exe
		$a_01_3 = {64 00 65 00 6c 00 74 00 61 00 76 00 65 00 72 00 73 00 2e 00 74 00 78 00 74 00 } //01 00  deltavers.txt
		$a_01_4 = {72 61 6e 64 6f 6d 73 74 75 66 66 } //01 00  randomstuff
		$a_01_5 = {57 65 62 43 6c 69 65 6e 74 } //01 00  WebClient
		$a_01_6 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //01 00  DownloadString
		$a_01_7 = {5a 69 70 46 69 6c 65 } //00 00  ZipFile
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_RPS_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.RPS!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {06 6f 5e 00 00 06 2d 06 73 a0 00 00 0a 7a 20 e8 03 00 00 28 9f 00 00 0a 06 12 02 6f 60 00 00 06 2c de } //00 00 
	condition:
		any of ($a_*)
 
}