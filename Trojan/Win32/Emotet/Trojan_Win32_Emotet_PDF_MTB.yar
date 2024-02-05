
rule Trojan_Win32_Emotet_PDF_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 cb 03 c1 99 b9 90 01 04 f7 f9 8a 5d 00 8d 4c 24 90 01 01 8a 94 14 90 01 04 32 da 88 5d 00 90 00 } //01 00 
		$a_81_1 = {72 43 4a 67 43 63 58 4d 77 66 66 32 4f 32 32 57 54 32 7a 39 38 38 73 61 66 59 72 78 55 62 68 46 6f } //00 00 
	condition:
		any of ($a_*)
 
}