
rule TrojanDropper_O97M_Simpdow_A{
	meta:
		description = "TrojanDropper:O97M/Simpdow.A,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {53 68 65 6c 6c 20 28 22 63 6d 64 2e 65 78 65 20 2f 63 20 50 6f 57 65 72 53 48 45 6c 4c 20 28 6e 45 57 2d 6f 42 6a 45 63 54 } //1 Shell ("cmd.exe /c PoWerSHElL (nEW-oBjEcT
		$a_00_1 = {2e 77 45 42 63 4c 69 45 6e 54 29 2e 64 4f 57 4e 4c 4f 61 64 66 49 6c 45 28 27 } //1 .wEBcLiEnT).dOWNLOadfIlE('
		$a_00_2 = {27 29 3b 26 73 74 61 72 74 20 25 54 45 4d 50 25 5c } //1 ');&start %TEMP%\
		$a_00_3 = {2e 65 78 65 26 20 65 78 69 74 22 29 } //1 .exe& exit")
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}