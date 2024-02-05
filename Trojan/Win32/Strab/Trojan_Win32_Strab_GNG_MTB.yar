
rule Trojan_Win32_Strab_GNG_MTB{
	meta:
		description = "Trojan:Win32/Strab.GNG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {88 55 ff 8b 45 f0 03 45 f4 8a 08 88 4d fe 0f b6 55 ff c1 fa 03 0f b6 45 ff c1 e0 05 0b d0 0f b6 4d fe 33 d1 8b 45 f8 88 90 01 05 8b 45 f4 83 c0 01 99 b9 90 01 04 f7 f9 89 55 f4 90 00 } //01 00 
		$a_01_1 = {4a 4b 62 74 67 64 66 64 } //00 00 
	condition:
		any of ($a_*)
 
}