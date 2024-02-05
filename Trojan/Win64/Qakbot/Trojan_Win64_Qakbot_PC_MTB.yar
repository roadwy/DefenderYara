
rule Trojan_Win64_Qakbot_PC_MTB{
	meta:
		description = "Trojan:Win64/Qakbot.PC!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 63 0c 24 48 8b 54 24 30 eb 1e 0f b6 04 01 8b 4c 24 04 eb 00 33 c8 8b c1 eb e5 8b 44 24 38 39 04 24 73 0a e9 14 ff ff ff 88 04 0a } //00 00 
	condition:
		any of ($a_*)
 
}