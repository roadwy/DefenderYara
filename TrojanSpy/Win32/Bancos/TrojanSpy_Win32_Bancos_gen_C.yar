
rule TrojanSpy_Win32_Bancos_gen_C{
	meta:
		description = "TrojanSpy:Win32/Bancos.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 0c 00 00 0b 00 "
		
	strings :
		$a_01_0 = {8b 45 f0 c1 e0 06 03 d8 89 5d f0 83 c7 06 83 ff 08 7c 48 83 ef 08 8b cf 8b 5d f0 d3 eb } //04 00 
		$a_01_1 = {62 6f 75 6e 64 61 72 79 3d 22 3d 5f 4e 65 78 74 50 61 72 74 5f 32 72 66 6b } //04 00  boundary="=_NextPart_2rfk
		$a_01_2 = {62 6f 75 6e 64 61 72 79 3d 22 3d 5f 4e 65 78 74 50 61 72 74 5f 32 72 65 6c } //02 00  boundary="=_NextPart_2rel
		$a_03_3 = {31 43 6c 69 63 6b 13 00 90 02 08 49 6d 61 67 65 90 02 03 43 6c 69 63 6b 90 00 } //02 00 
		$a_03_4 = {45 64 69 74 32 43 68 61 6e 67 65 90 02 10 45 64 69 74 33 43 68 61 6e 67 65 90 00 } //02 00 
		$a_02_5 = {63 6f 6e 66 69 72 6d 61 90 02 10 63 6c 69 63 6b 90 00 } //03 00 
		$a_02_6 = {53 65 6e 68 61 90 02 05 4b 65 79 50 72 65 73 73 90 00 } //03 00 
		$a_02_7 = {61 67 65 6e 63 69 61 90 02 10 63 6f 6e 74 61 90 00 } //02 00 
		$a_01_8 = {55 73 65 72 6e 61 6d 65 53 56 57 } //02 00  UsernameSVW
		$a_01_9 = {55 73 75 61 72 69 6f 2e 2e } //f4 ff  Usuario..
		$a_00_10 = {6f 6c 6d 5c 50 72 6f 74 65 73 74 6f } //f4 ff  olm\Protesto
		$a_01_11 = {74 72 69 65 73 74 65 2e 63 6f 6d 2e 62 72 } //00 00  trieste.com.br
	condition:
		any of ($a_*)
 
}