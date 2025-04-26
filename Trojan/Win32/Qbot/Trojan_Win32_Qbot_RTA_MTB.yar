
rule Trojan_Win32_Qbot_RTA_MTB{
	meta:
		description = "Trojan:Win32/Qbot.RTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 18 6a 01 e8 ?? ?? ?? ?? 8b d8 83 c3 04 6a 01 e8 ?? ?? ?? ?? 2b d8 01 1d ?? ?? ?? ?? 83 05 ?? ?? ?? ?? 04 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qbot_RTA_MTB_2{
	meta:
		description = "Trojan:Win32/Qbot.RTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c0 04 89 45 ?? 8b 45 ?? 3b 45 ?? 0f 82 ?? ?? ?? ?? c7 45 ?? 00 10 00 00 8b 45 ?? 03 45 ?? 2b 45 ?? 83 c0 04 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qbot_RTA_MTB_3{
	meta:
		description = "Trojan:Win32/Qbot.RTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {4d 69 66 44 74 7a 61 4d 68 67 47 } //MifDtzaMhgG  1
		$a_80_1 = {5a 48 78 62 45 54 6f 70 75 4f 49 } //ZHxbETopuOI  1
		$a_80_2 = {67 55 6d 61 6d 58 50 } //gUmamXP  1
		$a_80_3 = {6a 4b 75 45 6b 68 62 4d 6b 4d 68 59 4b 47 } //jKuEkhbMkMhYKG  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}