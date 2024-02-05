
rule Trojan_Win32_Emotet_DBI_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DBI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {f7 f7 8b fa 8a 54 3c 90 01 01 88 54 34 90 01 01 88 4c 3c 90 01 01 0f b6 44 34 90 01 01 0f b6 c9 03 c1 99 b9 90 01 04 f7 f9 8a 03 8a 54 14 90 01 01 32 c2 88 03 90 00 } //01 00 
		$a_02_1 = {f7 f7 33 c0 8b fa 8a 54 3c 90 01 01 88 54 34 90 01 01 8b 54 24 90 01 01 88 5c 3c 90 01 01 8a 44 34 90 01 01 81 e2 90 01 04 bb 90 01 04 03 c2 99 f7 fb 8a 19 8a 44 14 90 01 01 32 d8 88 19 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}