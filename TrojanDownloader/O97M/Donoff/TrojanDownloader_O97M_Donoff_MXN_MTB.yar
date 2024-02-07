
rule TrojanDownloader_O97M_Donoff_MXN_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.MXN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4f 75 74 6c 6f 6f 6b 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //01 00  CreateObject("Outlook.Application")
		$a_01_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 22 20 26 20 73 68 65 20 26 20 22 6c 22 29 } //01 00  CreateObject("wscript." & she & "l")
		$a_01_2 = {65 78 65 63 28 22 70 6f 77 65 22 20 26 20 22 72 73 68 65 6c 6c 20 2d 77 20 48 69 64 64 65 6e 20 49 6e 76 6f 6b 65 2d 57 65 62 52 65 71 75 65 73 74 20 2d 55 72 69 20 } //01 00  exec("powe" & "rshell -w Hidden Invoke-WebRequest -Uri 
		$a_03_3 = {43 68 72 28 33 34 29 20 26 20 22 68 74 74 70 3a 2f 2f 31 37 38 2e 31 37 2e 31 37 31 2e 31 34 34 2f 73 63 68 2f 90 02 0f 2e 65 78 22 90 00 } //01 00 
		$a_01_4 = {22 20 2d 4f 75 74 46 22 20 26 20 22 69 6c 65 20 22 } //00 00  " -OutF" & "ile "
	condition:
		any of ($a_*)
 
}