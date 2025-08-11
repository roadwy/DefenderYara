
rule TrojanDropper_Win64_BungeeDropper_A_dha{
	meta:
		description = "TrojanDropper:Win64/BungeeDropper.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_42_0 = {89 44 24 90 01 01 48 8b 44 24 90 01 01 48 05 fc 03 00 00 48 89 44 24 90 01 01 48 8b 44 24 90 01 01 48 05 f8 03 00 00 48 89 44 24 90 01 01 48 8b 44 24 90 01 01 8b 00 89 44 24 90 01 01 48 8b 44 24 90 00 00 } //1
	condition:
		((#a_42_0  & 1)*1) >=1
 
}