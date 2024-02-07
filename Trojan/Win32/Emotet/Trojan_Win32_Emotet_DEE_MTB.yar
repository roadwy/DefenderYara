
rule Trojan_Win32_Emotet_DEE_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DEE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 c2 99 b9 90 01 04 f7 f9 8b 4c 24 90 01 01 8b 84 24 90 01 04 8a 1c 01 8a 54 14 90 01 01 32 da 88 1c 01 90 02 04 89 4c 24 90 01 01 8b 8c 24 90 01 04 85 c9 0f 85 90 00 } //01 00 
		$a_81_1 = {6d 36 73 43 65 45 6d 4f 57 6c 33 36 31 66 77 39 51 58 44 50 74 65 56 31 5a 35 6a 77 31 39 57 6f 6a 62 } //00 00  m6sCeEmOWl361fw9QXDPteV1Z5jw19Wojb
	condition:
		any of ($a_*)
 
}