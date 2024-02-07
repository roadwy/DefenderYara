
rule TrojanSpy_Win32_Bancos_JX{
	meta:
		description = "TrojanSpy:Win32/Bancos.JX,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {44 72 69 76 65 72 20 4c 6f 61 64 65 64 } //01 00  Driver Loaded
		$a_00_1 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 48 00 61 00 72 00 64 00 64 00 69 00 73 00 6b 00 56 00 6f 00 6c 00 75 00 6d 00 65 00 31 00 5c 00 41 00 72 00 71 00 75 00 69 00 76 00 6f 00 73 00 20 00 64 00 65 00 20 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 61 00 73 00 5c 00 47 00 62 00 50 00 6c 00 75 00 67 00 69 00 6e 00 5c 00 67 00 62 00 70 00 73 00 76 00 2e 00 65 00 78 00 65 00 } //01 00  \Device\HarddiskVolume1\Arquivos de Programas\GbPlugin\gbpsv.exe
		$a_01_2 = {68 00 05 01 00 e8 d7 0c 00 00 83 c4 04 68 10 05 01 00 8d 8d 70 ff ff ff 51 ff 15 10 23 01 00 } //00 00 
	condition:
		any of ($a_*)
 
}