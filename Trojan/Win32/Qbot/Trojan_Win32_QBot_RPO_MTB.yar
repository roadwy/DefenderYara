
rule Trojan_Win32_QBot_RPO_MTB{
	meta:
		description = "Trojan:Win32/QBot.RPO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 7d 94 f3 a5 a4 6a 40 68 00 30 00 00 8b 45 0c 6b 08 03 51 6a 00 ff 15 90 01 04 89 45 dc c7 45 ec 00 00 00 00 8b 55 0c 8b 02 89 45 e4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}