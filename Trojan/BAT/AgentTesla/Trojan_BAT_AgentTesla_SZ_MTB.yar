
rule Trojan_BAT_AgentTesla_SZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {06 17 58 13 07 06 20 c0 e1 00 00 5d 0d 07 09 91 13 08 06 1f 16 5d 13 09 07 09 11 08 1f 16 8d 05 00 00 01 25 d0 15 00 00 04 28 90 01 03 0a 11 09 91 61 07 11 07 20 c0 e1 00 00 5d 91 20 00 01 00 00 58 20 00 01 00 00 5d 59 d2 9c 06 17 58 0a 06 20 c0 e1 00 00 fe 04 13 0a 11 0a 2d a3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}