
rule TrojanSpy_Win32_Bancos_ZX{
	meta:
		description = "TrojanSpy:Win32/Bancos.ZX,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {68 74 2a 74 70 73 3a 2f 2f 77 77 2a 77 2e 6e 2a 65 2e 62 72 61 64 65 2a 73 63 6f 2e 63 6f 6d 2e 2a 62 2a 72 2f 62 6f 6c 65 2a 74 6f 5f 6e 2a 69 2f 72 65 71 2a 41 67 65 6e 64 61 6d 65 6e 2a 74 6f 42 6f 6c 65 74 6f 4e 61 2a 6f 52 65 67 69 73 74 72 2a 61 64 6f 2e 64 6f 3f 63 64 2a 43 6f 6e 74 61 3d 30 26 63 64 4d 2a 65 6e 75 3d 31 37 26 63 64 41 6d 62 69 2a 65 6e 74 65 3d 31 26 74 70 43 6f 2a 6e 74 61 3d 43 26 43 54 2a 52 4c 3d } //03 00 
		$a_01_1 = {45 64 74 49 74 61 53 65 6e 68 61 43 61 72 74 61 6f } //00 00 
	condition:
		any of ($a_*)
 
}