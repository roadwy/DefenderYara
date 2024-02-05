
rule Trojan_Win32_Qbot_BM_MTB{
	meta:
		description = "Trojan:Win32/Qbot.BM!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8a 1c 3b 89 04 24 8b 44 24 18 0d c6 1c a1 4e 01 f2 88 d7 0f b6 d7 8b 74 24 20 89 74 24 74 89 44 24 70 8a 7c 24 6b 80 c7 a0 8b 44 24 14 8a 04 10 30 d8 88 7c 24 6b 8b 54 24 28 88 04 3a } //00 00 
	condition:
		any of ($a_*)
 
}