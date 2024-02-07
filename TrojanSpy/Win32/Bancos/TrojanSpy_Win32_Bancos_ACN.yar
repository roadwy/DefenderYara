
rule TrojanSpy_Win32_Bancos_ACN{
	meta:
		description = "TrojanSpy:Win32/Bancos.ACN,SIGNATURE_TYPE_PEHSTR,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 6e 73 65 72 74 20 69 6e 74 6f 20 54 41 42 5f 53 55 4c 5f 54 41 42 28 64 61 74 61 63 61 64 61 73 74 72 6f 2c 6d 61 63 61 64 64 72 65 73 73 2c 70 63 } //01 00  Insert into TAB_SUL_TAB(datacadastro,macaddress,pc
		$a_01_1 = {3c 42 52 3e 3c 53 50 41 4e 20 63 6c 61 73 73 3d 69 74 65 6e 73 44 61 64 6f 73 43 61 72 74 61 6f 41 75 72 61 } //01 00  <BR><SPAN class=itensDadosCartaoAura
		$a_01_2 = {75 70 64 61 74 65 20 54 41 42 5f 43 45 54 45 4c 45 4d 5f 54 41 42 20 73 65 74 20 73 74 61 74 75 73 3d } //01 00  update TAB_CETELEM_TAB set status=
		$a_01_3 = {53 65 6e 68 61 20 45 6e 76 69 61 64 61 20 63 6f 6d 20 73 75 63 65 73 73 6f 2e 2e 2e 21 21 21 } //01 00  Senha Enviada com sucesso...!!!
		$a_01_4 = {42 61 6e 72 69 73 75 6c 20 48 6f 6d 65 42 40 6e 6b 69 6e 67 00 } //01 00 
		$a_01_5 = {6e 74 2e 50 43 5f 37 5f 30 4d 51 54 52 39 4b 32 31 30 53 47 37 30 } //00 00  nt.PC_7_0MQTR9K210SG70
	condition:
		any of ($a_*)
 
}