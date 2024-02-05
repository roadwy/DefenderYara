
rule TrojanDownloader_Win32_Garveep_F{
	meta:
		description = "TrojanDownloader:Win32/Garveep.F,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {f3 ab 66 ab 90 02 10 ff 15 90 02 01 20 40 00 80 3e 25 0f 85 bb 00 00 00 90 00 } //01 00 
		$a_00_1 = {41 6e 74 69 53 70 79 57 61 72 65 32 47 75 61 72 64 2e 65 78 65 } //01 00 
		$a_00_2 = {52 30 33 41 43 37 46 30 } //01 00 
		$a_00_3 = {56 33 4c 53 76 63 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}