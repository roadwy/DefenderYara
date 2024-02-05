
rule Trojan_Win64_Bokbot_DA_MTB{
	meta:
		description = "Trojan:Win64/Bokbot.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 44 24 40 8a 4c 24 48 0b c8 88 4c 24 40 8a 44 24 48 02 c0 88 44 24 48 8a 44 24 50 fe c8 88 44 24 50 8a 44 24 50 84 c0 75 90 01 01 0f b6 44 24 40 8a 4c 24 58 33 c8 88 4c 24 40 8a 44 24 58 fe c0 88 44 24 58 8a 44 24 40 41 88 00 49 ff c0 83 c3 ff 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}