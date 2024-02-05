
rule Trojan_Win32_Qbot_NXA_MTB{
	meta:
		description = "Trojan:Win32/Qbot.NXA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b f8 a1 a4 90 4a 00 8b 14 24 c1 e2 08 2b d7 d1 ea 03 d7 c1 ea 11 30 14 18 43 8b 0d 3c 94 4a 00 3b d9 72 9f } //01 00 
		$a_01_1 = {83 ec 28 64 a1 30 00 00 00 66 3b db } //01 00 
		$a_01_2 = {4d 6f 74 64 } //00 00 
	condition:
		any of ($a_*)
 
}