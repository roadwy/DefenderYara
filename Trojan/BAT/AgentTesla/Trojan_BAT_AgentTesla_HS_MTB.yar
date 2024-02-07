
rule Trojan_BAT_AgentTesla_HS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.HS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {4e 65 62 75 6c 61 5f 5f 57 65 62 5f 42 72 6f 77 73 65 72 5f 2e 52 65 73 6f 75 72 63 65 73 } //01 00  Nebula__Web_Browser_.Resources
		$a_81_1 = {42 49 47 5f 44 49 53 43 4f 52 44 5f 4c 49 4e 4b 5f 53 54 52 49 4e 47 } //01 00  BIG_DISCORD_LINK_STRING
		$a_81_2 = {57 65 62 42 72 6f 77 73 65 72 31 } //01 00  WebBrowser1
		$a_81_3 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //01 00  DownloadString
		$a_81_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_5 = {41 63 74 69 76 61 74 6f 72 } //00 00  Activator
	condition:
		any of ($a_*)
 
}