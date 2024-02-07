
rule Trojan_Win32_Emotet_DDH_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DDH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a d0 89 4c 24 90 01 01 0a 44 24 90 01 01 f6 d2 f6 d1 0a d1 22 d0 8b 44 24 90 01 01 88 10 90 00 } //01 00 
		$a_81_1 = {32 59 50 5a 68 4e 6d 46 32 4b 6b 67 32 4b 72 59 73 64 69 74 32 59 72 59 3d } //00 00  2YPZhNmF2Kkg2KrYsdit2YrY=
	condition:
		any of ($a_*)
 
}