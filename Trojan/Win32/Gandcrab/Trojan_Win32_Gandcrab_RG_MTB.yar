
rule Trojan_Win32_Gandcrab_RG_MTB{
	meta:
		description = "Trojan:Win32/Gandcrab.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {a1 6c a2 40 00 03 85 90 01 04 8b 0d b4 aa 40 00 03 8d 90 01 04 8a 89 a0 ec 0b 00 88 08 81 bd 90 01 04 22 06 00 00 7d 90 00 } //01 00 
		$a_00_1 = {03 45 e4 8b 4d d4 03 4d ec 33 c1 8b 4d d4 c1 e9 05 03 4d e8 33 c1 8b 4d f0 2b c8 89 4d f0 81 7d fc 49 02 } //00 00 
	condition:
		any of ($a_*)
 
}