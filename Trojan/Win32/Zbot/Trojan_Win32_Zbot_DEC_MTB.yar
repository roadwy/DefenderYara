
rule Trojan_Win32_Zbot_DEC_MTB{
	meta:
		description = "Trojan:Win32/Zbot.DEC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {03 f0 8b 45 08 03 30 8b 4d 08 89 31 8b 55 08 8b 02 2d 87 10 00 00 8b 4d 08 89 01 } //01 00 
		$a_81_1 = {30 38 72 74 67 30 69 6d 75 77 72 68 39 79 33 75 6a 34 35 30 79 69 6a 33 74 } //00 00  08rtg0imuwrh9y3uj450yij3t
	condition:
		any of ($a_*)
 
}