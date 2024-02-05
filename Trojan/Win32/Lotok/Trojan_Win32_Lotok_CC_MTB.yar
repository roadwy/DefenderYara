
rule Trojan_Win32_Lotok_CC_MTB{
	meta:
		description = "Trojan:Win32/Lotok.CC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 83 fe 01 75 02 33 f6 8a 14 39 0f b7 c6 80 ea 7a 8a 44 45 12 32 c2 46 88 04 39 41 3b 4d 0c 7c df } //01 00 
		$a_01_1 = {33 f6 8b 45 08 8d 0c 02 0f b7 c6 8a 44 45 ec 30 01 46 42 3b d7 72 e3 } //00 00 
	condition:
		any of ($a_*)
 
}