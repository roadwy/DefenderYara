
rule Trojan_Win32_Bancos_B{
	meta:
		description = "Trojan:Win32/Bancos.B,SIGNATURE_TYPE_PEHSTR,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 00 61 00 6c 00 68 00 61 00 20 00 61 00 6f 00 20 00 63 00 61 00 72 00 72 00 65 00 67 00 61 00 72 00 20 00 76 00 69 00 64 00 65 00 6f 00 } //01 00  Falha ao carregar video
		$a_01_1 = {66 00 69 00 76 00 65 00 35 00 5c 00 63 00 64 00 61 00 66 00 } //01 00  five5\cdaf
		$a_01_2 = {4d 6f 6e 69 74 6f 72 61 45 6e 76 69 6f 44 65 44 61 64 6f 73 } //01 00  MonitoraEnvioDeDados
		$a_01_3 = {45 6e 76 69 61 4d 61 69 6c 43 6f 70 } //01 00  EnviaMailCop
		$a_01_4 = {42 61 69 78 61 72 41 72 71 75 69 76 6f 73 } //01 00  BaixarArquivos
		$a_01_5 = {43 6f 6e 74 61 6d 69 6e 61 41 6c 74 } //00 00  ContaminaAlt
	condition:
		any of ($a_*)
 
}