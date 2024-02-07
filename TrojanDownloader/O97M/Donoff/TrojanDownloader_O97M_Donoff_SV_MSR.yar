
rule TrojanDownloader_O97M_Donoff_SV_MSR{
	meta:
		description = "TrojanDownloader:O97M/Donoff.SV!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {22 43 3a 5c 55 73 65 72 22 20 26 20 22 73 5c 50 75 62 22 20 26 20 22 6c 69 63 5c 56 69 65 77 2e 6c 22 20 26 20 22 6e 6b 22 } //01 00  "C:\User" & "s\Pub" & "lic\View.l" & "nk"
		$a_01_1 = {73 6f 2e 54 61 72 67 65 74 50 61 74 68 20 3d 20 22 6d 73 68 74 22 20 26 20 22 61 2e 65 22 20 26 20 22 78 65 22 } //01 00  so.TargetPath = "msht" & "a.e" & "xe"
		$a_01_2 = {73 6f 2e 41 72 67 75 6d 65 6e 74 73 20 3d 20 22 68 74 74 22 20 26 20 22 70 73 3a 2f 2f 62 69 74 22 20 26 20 22 2e 22 20 26 20 22 6c 79 2f } //00 00  so.Arguments = "htt" & "ps://bit" & "." & "ly/
	condition:
		any of ($a_*)
 
}