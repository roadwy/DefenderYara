
rule TrojanDownloader_Win32_Wolfic_E{
	meta:
		description = "TrojanDownloader:Win32/Wolfic.E,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {32 00 37 00 45 00 35 00 37 00 44 00 38 00 34 00 2d 00 34 00 33 00 31 00 30 00 2d 00 34 00 38 00 32 00 35 00 2d 00 41 00 42 00 32 00 32 00 2d 00 37 00 34 00 33 00 43 00 37 00 38 00 42 00 38 00 46 00 33 00 41 00 41 00 20 00 } //02 00 
		$a_80_1 = {48 69 6a 61 63 6b 69 6e 67 4c 69 62 2e 64 6c 6c } //HijackingLib.dll  01 00 
		$a_80_2 = {5c 64 75 73 65 72 2e 64 6c 6c 2e 49 73 53 74 61 72 74 44 65 6c 65 74 65 } //\duser.dll.IsStartDelete  01 00 
		$a_80_3 = {5c 64 75 73 65 72 2e 64 6c 6c 2e 49 6e 76 61 6c 69 64 61 74 65 47 61 64 67 65 74 } //\duser.dll.InvalidateGadget  00 00 
	condition:
		any of ($a_*)
 
}