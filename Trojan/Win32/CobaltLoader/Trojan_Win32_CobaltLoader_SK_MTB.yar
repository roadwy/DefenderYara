
rule Trojan_Win32_CobaltLoader_SK_MTB{
	meta:
		description = "Trojan:Win32/CobaltLoader.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_02_0 = {8d 4d fc 53 51 56 57 50 ff 15 90 01 02 00 10 85 c0 74 1c 33 c0 39 5d fc 76 0a 80 34 38 90 01 01 40 3b 45 fc 72 f6 ff 75 f8 ff 15 90 01 02 00 10 ff d7 90 00 } //02 00 
		$a_02_1 = {55 8b ec 51 51 53 56 57 6a 04 be 90 01 02 10 00 68 00 10 00 00 33 db 56 53 ff 15 90 01 02 00 10 8b f8 3b fb 74 4d 53 53 6a 03 53 6a 01 68 00 00 00 80 68 90 01 02 00 10 ff 15 90 01 02 00 10 83 f8 ff 89 45 f8 74 2e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}