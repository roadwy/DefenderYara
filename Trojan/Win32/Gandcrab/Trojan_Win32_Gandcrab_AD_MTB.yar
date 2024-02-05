
rule Trojan_Win32_Gandcrab_AD_MTB{
	meta:
		description = "Trojan:Win32/Gandcrab.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 44 19 01 0f b6 14 19 88 54 24 90 01 01 88 44 24 90 01 01 8a 44 19 90 01 01 8a d0 c0 e2 90 01 01 0a 54 19 90 01 01 8d 74 24 90 01 01 8d 7c 24 90 01 01 88 54 24 90 01 01 e8 90 00 } //01 00 
		$a_02_1 = {0f b6 4c 24 90 01 01 8b 44 24 90 01 01 0f b6 54 24 90 01 01 88 0c 28 0f b6 4c 24 90 01 01 45 88 14 28 8b 54 24 90 01 01 45 88 0c 28 83 c3 04 45 3b 1a 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}