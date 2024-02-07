
rule TrojanSpy_Win32_Bancos_AHB{
	meta:
		description = "TrojanSpy:Win32/Bancos.AHB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {2f 69 6e 66 65 63 74 73 2f 61 76 69 73 6f 2e 70 68 70 } //02 00  /infects/aviso.php
		$a_01_1 = {2f 69 6e 66 65 63 74 73 2f 69 6e 66 6f 2e 70 68 70 } //01 00  /infects/info.php
		$a_01_2 = {73 65 6e 68 61 3d 44 41 54 41 2e 2e 3a } //01 00  senha=DATA..:
		$a_01_3 = {48 4f 52 41 53 2e 2e 3a } //01 00  HORAS..:
		$a_01_4 = {43 6f 70 20 4c 54 44 41 2e 2e 2e } //00 00  Cop LTDA...
	condition:
		any of ($a_*)
 
}