
rule Trojan_Win64_Trubot_ZF_MTB{
	meta:
		description = "Trojan:Win64/Trubot.ZF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f af c8 8b c1 33 d2 b9 05 00 00 00 f7 f1 8b c2 88 44 24 90 01 01 0f b6 44 24 90 01 01 0f b6 c8 8b 05 90 01 04 d3 e8 0f be 4c 24 90 01 01 0f b6 54 24 90 01 01 03 ca 2b 0d 90 01 04 33 c1 0f be 0d 90 01 04 2b c8 8b c1 88 05 90 01 04 0f be 44 24 90 01 01 99 b9 05 00 00 00 f7 f9 8b 0d 90 01 04 03 c8 8b c1 88 44 24 90 01 01 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}