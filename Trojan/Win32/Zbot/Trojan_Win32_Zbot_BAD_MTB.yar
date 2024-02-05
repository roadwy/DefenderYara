
rule Trojan_Win32_Zbot_BAD_MTB{
	meta:
		description = "Trojan:Win32/Zbot.BAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {8d 44 24 10 8d 4c 24 20 50 51 6a 00 6a 00 6a 0c 6a 00 6a 00 8d 94 24 84 01 00 00 6a 00 52 6a 00 ff 15 40 20 40 00 85 c0 74 28 8b 44 24 10 6a 40 } //02 00 
		$a_01_1 = {15 b4 20 40 00 56 ff 15 b8 20 40 00 57 ff 15 bc 20 40 00 8b b4 24 48 02 00 00 8d 54 24 30 56 52 ff 15 c0 20 40 00 6a 06 56 ff 15 c4 20 40 00 8d 44 24 30 50 ff 15 c8 } //00 00 
	condition:
		any of ($a_*)
 
}