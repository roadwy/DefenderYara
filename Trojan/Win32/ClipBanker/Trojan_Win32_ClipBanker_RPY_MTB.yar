
rule Trojan_Win32_ClipBanker_RPY_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 08 8b 5e 14 8a 0c b8 2a ca 8b 56 10 88 4d e4 3b d3 73 19 8d 42 01 89 46 10 8b c6 83 fb 10 72 02 8b 06 88 0c 10 c6 44 10 01 00 eb 12 } //00 00 
	condition:
		any of ($a_*)
 
}