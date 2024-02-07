
rule Trojan_Win32_AgentTesla_ST_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.ST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {10 b1 f8 40 90 02 04 81 c1 90 20 39 cb 75 90 01 01 38 ed 90 00 } //01 00 
		$a_03_1 = {68 80 54 00 00 90 02 06 5b 90 01 02 83 eb 02 90 02 06 83 eb 02 90 01 02 8b 14 1f 90 02 18 31 f2 90 02 30 09 14 18 90 02 15 7f 90 02 10 89 c2 90 02 10 c3 90 00 } //00 00 
		$a_00_2 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}