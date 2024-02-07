
rule TrojanSpy_Win32_Bancos_WJ{
	meta:
		description = "TrojanSpy:Win32/Bancos.WJ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {4e 00 6f 00 6d 00 65 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 5b 00 20 00 49 00 4e 00 46 00 45 00 43 00 54 00 41 00 44 00 4f 00 20 00 5d 00 } //01 00  Nome======[ INFECTADO ]
		$a_00_1 = {5c 00 53 00 57 00 4f 00 44 00 4e 00 49 00 57 00 5c 00 3a 00 43 00 } //01 00  \SWODNIW\:C
		$a_01_2 = {72 65 67 73 76 72 33 32 20 2f 75 20 2f 73 20 22 43 3a 5c 61 72 71 75 69 76 6f 73 20 64 65 20 70 72 6f 67 72 61 6d 61 73 5c } //00 00  regsvr32 /u /s "C:\arquivos de programas\
	condition:
		any of ($a_*)
 
}