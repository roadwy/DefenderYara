
rule TrojanSpy_AndroidOS_TwMobo_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/TwMobo.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {41 75 74 6f 42 6f 74 3a 3a 53 6f 63 6b 65 74 3a 3a 43 6f 6e 74 72 6f 6c 65 } //01 00  AutoBot::Socket::Controle
		$a_00_1 = {63 6f 6d 2f 67 73 65 72 76 69 63 65 2f 72 65 63 65 69 76 65 72 2f 41 64 6d 52 3b } //01 00  com/gservice/receiver/AdmR;
		$a_00_2 = {61 75 74 6f 62 6f 74 2f 41 63 65 73 73 69 62 69 6c 69 64 61 64 65 } //01 00  autobot/Acessibilidade
		$a_00_3 = {41 63 65 73 73 69 62 69 6c 69 64 61 64 65 5f 43 6c 69 63 6b } //01 00  Acessibilidade_Click
		$a_00_4 = {41 63 65 73 73 69 62 69 6c 69 64 61 64 65 5f 53 6f 63 6b 65 74 43 6f 6e 74 72 6f 6c 65 } //01 00  Acessibilidade_SocketControle
		$a_00_5 = {63 6f 6e 74 72 6f 6c 65 5f 72 65 6d 6f 74 6f } //00 00  controle_remoto
		$a_00_6 = {5d 04 00 00 } //03 8e 
	condition:
		any of ($a_*)
 
}