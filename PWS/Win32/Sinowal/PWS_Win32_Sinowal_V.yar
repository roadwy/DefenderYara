
rule PWS_Win32_Sinowal_V{
	meta:
		description = "PWS:Win32/Sinowal.V,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 64 64 50 72 69 6e 74 50 72 6f 76 69 64 6f 72 41 } //01 00  AddPrintProvidorA
		$a_00_1 = {5c 5c 2e 5c 46 6c 74 4d 67 72 00 } //01 00 
		$a_03_2 = {8b 45 fc 8b 48 3c 89 4d f8 8b 55 fc 03 55 f8 0f b7 42 16 0d 00 20 00 00 8b 4d fc 03 4d f8 66 89 41 16 8b 55 90 01 01 52 8b 45 fc 50 8b 4d 08 51 e8 90 01 04 83 c4 0c 89 45 f4 33 d2 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}