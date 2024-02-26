
rule Trojan_Win32_KeyLogger_AKI_MTB{
	meta:
		description = "Trojan:Win32/KeyLogger.AKI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 33 30 31 4b 69 72 61 } //01 00  3301Kira
		$a_01_1 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 64 00 65 00 66 00 39 00 62 00 36 00 63 00 64 00 33 00 66 00 32 00 62 00 30 00 63 00 34 00 33 00 30 00 39 00 37 00 64 00 66 00 62 00 63 00 39 00 31 00 38 00 38 00 36 00 32 00 62 00 38 00 32 00 } //00 00  Software\def9b6cd3f2b0c43097dfbc918862b82
	condition:
		any of ($a_*)
 
}