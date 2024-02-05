
rule Trojan_Win32_AgentTesla_SH_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.SH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 a8 21 a7 3e 90 02 06 eb 90 02 91 81 c1 99 1f 9a 02 90 02 15 eb 90 02 20 8b 17 90 02 10 39 ca 75 90 00 } //01 00 
		$a_03_1 = {89 0c 18 eb 90 0a 00 20 4b 90 02 70 4b 90 02 40 4b 90 02 40 4b 90 02 70 8b 0c 1f 90 02 50 31 f1 90 02 70 89 0c 18 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}