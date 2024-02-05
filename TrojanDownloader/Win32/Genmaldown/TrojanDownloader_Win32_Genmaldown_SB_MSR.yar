
rule TrojanDownloader_Win32_Genmaldown_SB_MSR{
	meta:
		description = "TrojanDownloader:Win32/Genmaldown.SB!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 31 35 2e 32 38 2e 33 32 2e 31 32 } //01 00 
		$a_01_1 = {57 72 69 74 65 4d 62 6f 78 2e 65 78 65 } //01 00 
		$a_01_2 = {43 6f 6e 6e 65 63 74 69 6f 6e 3a 20 63 6c 6f 73 65 } //01 00 
		$a_01_3 = {62 38 36 31 63 62 35 36 34 35 38 63 66 64 37 33 31 36 34 37 35 32 35 64 64 30 39 37 66 66 31 36 } //00 00 
	condition:
		any of ($a_*)
 
}