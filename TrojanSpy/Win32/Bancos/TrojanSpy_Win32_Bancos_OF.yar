
rule TrojanSpy_Win32_Bancos_OF{
	meta:
		description = "TrojanSpy:Win32/Bancos.OF,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 49 4e 46 45 43 54 3a 20 00 } //01 00  䤽䙎䍅㩔 
		$a_01_1 = {3d 50 48 49 53 48 49 4e 47 3a 20 00 } //01 00  倽䥈䡓义㩇 
		$a_01_2 = {42 72 61 64 65 73 63 6f 5f 53 65 67 75 72 61 6e 63 61 00 } //01 00 
		$a_01_3 = {53 65 6e 68 61 20 64 6f 20 43 61 72 74 e3 6f 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 3a 00 } //00 00 
	condition:
		any of ($a_*)
 
}