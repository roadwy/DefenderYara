
rule TrojanDownloader_Win32_Dofoil_gen_D{
	meta:
		description = "TrojanDownloader:Win32/Dofoil.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {32 28 c1 c1 08 32 cd 40 80 38 00 75 f3 31 d1 75 } //01 00 
		$a_01_1 = {6a 40 68 00 30 00 00 8b 46 50 50 6a 00 ff 93 } //00 00 
	condition:
		any of ($a_*)
 
}