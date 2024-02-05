
rule Trojan_Win32_Emotet_PSV_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PSV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 84 34 90 01 04 0f b6 cb 03 c1 99 b9 90 01 04 f7 f9 8a 5d 00 8a 94 14 90 01 04 32 da 88 5d 00 90 00 } //01 00 
		$a_81_1 = {30 64 71 6b 69 7a 4c 50 62 6c 65 7a 37 33 6b 30 6b 43 77 4d 47 71 6a 66 7a 70 33 72 57 67 65 68 45 73 46 74 } //00 00 
	condition:
		any of ($a_*)
 
}