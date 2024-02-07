
rule TrojanDownloader_Win32_VidarStealer_SIB_MTB{
	meta:
		description = "TrojanDownloader:Win32/VidarStealer.SIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {43 6f 6e 74 72 6f 6c 4f 66 73 30 30 34 30 30 30 30 30 30 30 30 30 30 41 33 34 } //01 00  ControlOfs0040000000000A34
		$a_00_1 = {44 24 4c 50 6b 44 24 58 64 50 56 } //01 00  D$LPkD$XdPV
		$a_03_2 = {8b d8 8b 45 90 01 01 8b 00 03 45 90 01 01 03 d8 90 02 20 2b d8 8b 45 90 1b 00 89 18 90 02 20 8b 90 03 01 01 45 55 90 1b 00 31 90 03 01 01 18 02 90 02 20 8b d8 90 02 20 2b d8 90 02 20 8b 45 90 1b 01 3b 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}