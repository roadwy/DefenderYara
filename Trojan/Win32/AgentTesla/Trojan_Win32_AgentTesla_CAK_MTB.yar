
rule Trojan_Win32_AgentTesla_CAK_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.CAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 33 d2 f7 75 14 8b 45 10 0f b6 0c 10 8b 55 08 03 55 fc 0f b6 02 2b c1 8b 4d 08 03 4d fc 88 01 eb } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}