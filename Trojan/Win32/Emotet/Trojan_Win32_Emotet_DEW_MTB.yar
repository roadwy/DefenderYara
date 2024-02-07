
rule Trojan_Win32_Emotet_DEW_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DEW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 c1 0f b6 4d 0f 89 45 f0 8b 45 ec 0f b6 84 05 90 01 04 03 c1 8b cb 99 f7 f9 8b 45 f0 8a 8c 15 90 1b 00 30 08 90 00 } //01 00 
		$a_02_1 = {33 c0 81 e1 ff 00 00 00 8a 84 14 90 01 04 03 c1 b9 cf 08 00 00 99 f7 f9 8b 84 24 90 01 04 8b 8c 24 90 01 04 8a 94 14 90 1b 00 30 14 08 90 00 } //01 00 
		$a_81_2 = {53 57 46 74 43 6d 77 78 52 76 4f 71 51 48 50 43 79 49 63 33 64 35 4b 52 36 70 56 39 33 54 47 6b 52 61 58 } //00 00  SWFtCmwxRvOqQHPCyIc3d5KR6pV93TGkRaX
	condition:
		any of ($a_*)
 
}