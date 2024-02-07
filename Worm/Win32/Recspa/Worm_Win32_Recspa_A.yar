
rule Worm_Win32_Recspa_A{
	meta:
		description = "Worm:Win32/Recspa.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 04 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {3a c4 fe 12 00 fb ef 64 fe 60 31 24 ff 36 06 00 84 fe 74 fe 64 fe 00 0f 6c 24 ff 04 14 ff 55 f4 ff fe 5d 20 00 00 56 04 14 ff 55 1b 13 00 1b 14 00 2a 23 04 ff 1b 15 00 2a } //02 00 
		$a_01_1 = {3a 50 ff 37 00 5d fb 33 35 40 ff 1c 7f 01 08 08 00 06 34 00 4d 60 ff 03 40 0a 38 00 04 00 6c 78 ff 1b 39 00 fb 30 1c 9d 01 3a } //01 00 
		$a_00_2 = {5b 00 41 00 75 00 74 00 6f 00 72 00 75 00 6e 00 5d 00 } //01 00  [Autorun]
		$a_00_3 = {45 00 73 00 70 00 69 00 61 00 72 00 } //01 00  Espiar
		$a_00_4 = {45 00 6e 00 76 00 69 00 6f 00 20 00 64 00 65 00 20 00 69 00 6d 00 61 00 67 00 65 00 6e 00 20 00 63 00 6f 00 6d 00 70 00 6c 00 65 00 74 00 6f 00 } //01 00  Envio de imagen completo
		$a_00_5 = {52 00 65 00 63 00 69 00 62 00 69 00 72 00 20 00 55 00 6e 00 69 00 64 00 61 00 64 00 65 00 73 00 } //00 00  Recibir Unidades
	condition:
		any of ($a_*)
 
}