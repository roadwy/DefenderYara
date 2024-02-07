
rule TrojanDownloader_O97M_Powdow_PRA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.PRA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {6b 61 6f 73 6b 2e 63 6f 70 79 66 69 6c 65 20 22 43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 6d 73 68 74 61 2e 65 78 65 22 2c 20 22 43 3a 5c 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 5c 63 6f 6e 64 2e 63 6f 6d 22 2c 20 54 72 75 65 } //01 00  kaosk.copyfile "C:\Windows\System32\mshta.exe", "C:\\ProgramData\\cond.com", True
		$a_01_1 = {3d 20 22 43 3a 6d 6d 6d 6d 6d 6d 6d 6d 44 4c 41 53 44 4c 6c 72 6f 67 72 61 6d 44 61 74 61 6d 6d 6d 6d 6d 6d 6d 6d 63 6f 6e 64 30 6c 6f 6c 20 68 6d 6f 74 61 6d 6f 74 61 44 4c 41 53 44 4c 6c 73 3a 73 65 78 73 65 78 6d 69 73 6c 61 6c 6d 69 73 6c 61 6c 6d 69 73 6c 61 6c 30 62 69 6d 6f 74 61 6c 79 30 6c 6f 6c 73 65 78 22 } //00 00  = "C:mmmmmmmmDLASDLlrogramDatammmmmmmmcond0lol hmotamotaDLASDLls:sexsexmislalmislalmislal0bimotaly0lolsex"
	condition:
		any of ($a_*)
 
}