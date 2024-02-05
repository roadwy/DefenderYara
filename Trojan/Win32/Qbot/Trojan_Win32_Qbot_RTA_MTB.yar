
rule Trojan_Win32_Qbot_RTA_MTB{
	meta:
		description = "Trojan:Win32/Qbot.RTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {31 18 6a 01 e8 90 01 04 8b d8 83 c3 04 6a 01 e8 90 01 04 2b d8 01 1d 90 01 04 83 05 90 01 04 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qbot_RTA_MTB_2{
	meta:
		description = "Trojan:Win32/Qbot.RTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 c0 04 89 45 90 01 01 8b 45 90 01 01 3b 45 90 01 01 0f 82 90 01 04 c7 45 90 01 01 00 10 00 00 8b 45 90 01 01 03 45 90 01 01 2b 45 90 01 01 83 c0 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qbot_RTA_MTB_3{
	meta:
		description = "Trojan:Win32/Qbot.RTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_80_0 = {4d 69 66 44 74 7a 61 4d 68 67 47 } //MifDtzaMhgG  01 00 
		$a_80_1 = {5a 48 78 62 45 54 6f 70 75 4f 49 } //ZHxbETopuOI  01 00 
		$a_80_2 = {67 55 6d 61 6d 58 50 } //gUmamXP  01 00 
		$a_80_3 = {6a 4b 75 45 6b 68 62 4d 6b 4d 68 59 4b 47 } //jKuEkhbMkMhYKG  00 00 
	condition:
		any of ($a_*)
 
}