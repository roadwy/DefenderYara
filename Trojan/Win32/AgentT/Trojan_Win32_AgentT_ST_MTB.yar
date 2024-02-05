
rule Trojan_Win32_AgentT_ST_MTB{
	meta:
		description = "Trojan:Win32/AgentT.ST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {4e 81 ce 00 ff ff ff 46 8a 84 35 90 01 04 88 84 1d 90 01 04 8b 45 90 01 01 88 8c 35 90 01 04 0f b6 8c 1d 90 01 04 03 ca 0f b6 c9 8a 8c 0d 90 01 04 30 0c 38 40 89 45 90 01 01 3b 45 10 72 90 00 } //01 00 
		$a_03_1 = {59 8b c8 33 d2 8b c6 f7 f1 8a 0c 1a 30 0c 3e 46 3b 75 90 01 01 72 90 00 } //00 00 
		$a_00_2 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}