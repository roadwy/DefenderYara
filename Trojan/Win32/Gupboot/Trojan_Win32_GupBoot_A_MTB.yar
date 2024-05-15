
rule Trojan_Win32_GupBoot_A_MTB{
	meta:
		description = "Trojan:Win32/GupBoot.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {66 85 dd 66 2b d4 66 33 d4 64 8b 10 66 0f ab e0 66 c1 e0 90 01 01 d2 c0 89 54 25 90 01 01 c1 f0 90 01 01 0f b7 c7 80 dc 90 01 01 8b 07 f5 66 3b c4 8d bf 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}