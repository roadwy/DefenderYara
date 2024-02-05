
rule TrojanDownloader_Win32_Stocde_A_bit{
	meta:
		description = "TrojanDownloader:Win32/Stocde.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6d 64 73 68 65 6c 6c 5f 64 65 69 6e 69 74 } //01 00 
		$a_01_1 = {73 74 6f 70 20 73 68 61 72 65 64 61 63 63 65 73 73 } //01 00 
		$a_01_2 = {5c 25 63 25 63 25 63 25 63 25 63 2e 65 78 65 } //01 00 
		$a_01_3 = {2e 65 78 65 00 00 00 68 74 74 70 3a 2f 2f } //00 00 
	condition:
		any of ($a_*)
 
}