
rule Trojan_Win32_Bandit_GA_MTB{
	meta:
		description = "Trojan:Win32/Bandit.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {81 ff 69 04 00 00 75 90 01 01 53 ff 15 90 01 04 8b 45 08 8d 0c 06 e8 90 01 04 30 01 46 3b f7 7c 90 01 01 5e 5b c9 c2 90 00 } //01 00 
		$a_02_1 = {3d 82 03 00 00 75 90 01 01 57 57 57 ff 15 90 01 04 a1 90 01 04 8b 0d 90 01 04 8a 8c 31 f5 d0 00 00 8b 15 90 01 04 88 0c 32 46 3b f0 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}