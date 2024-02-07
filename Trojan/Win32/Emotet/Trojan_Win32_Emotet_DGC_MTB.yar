
rule Trojan_Win32_Emotet_DGC_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DGC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 07 0f b6 cb 03 c1 99 8b ce f7 f9 8b 85 90 01 04 8a 8c 15 90 01 04 30 08 90 00 } //01 00 
		$a_81_1 = {68 78 55 4a 48 47 59 51 4e 50 51 63 43 67 4d 68 4d 79 52 43 73 30 4f 68 62 57 7a 58 6d 6f 6a 36 59 } //00 00  hxUJHGYQNPQcCgMhMyRCs0OhbWzXmoj6Y
	condition:
		any of ($a_*)
 
}