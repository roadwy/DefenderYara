
rule Trojan_Win32_Delf_JG{
	meta:
		description = "Trojan:Win32/Delf.JG,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_02_0 = {eb 05 bf 01 00 00 00 8b 45 f4 0f b6 5c 38 ff 33 5d e0 3b 5d e4 7f 90 01 01 81 c3 ff 00 00 00 2b 5d e4 eb 90 00 } //01 00 
		$a_00_1 = {46 6f 72 e7 61 6e 64 6f 20 55 50 44 41 54 45 } //01 00 
		$a_00_2 = {3f 61 3d 63 26 73 3d 25 73 26 70 3d 25 64 26 69 64 3d 25 73 } //01 00  ?a=c&s=%s&p=%d&id=%s
		$a_00_3 = {50 72 6f 6a 65 74 6f 73 5c 6a 61 76 61 6e 5c 62 68 6f 5f 61 74 75 61 6c 5c 75 6e 74 46 75 6e 63 6f 65 73 2e 70 61 73 } //01 00  Projetos\javan\bho_atual\untFuncoes.pas
		$a_00_4 = {43 61 72 72 65 67 61 6e 64 6f 20 64 6f 20 63 6f 6e 74 65 } //01 00  Carregando do conte
		$a_00_5 = {75 6d 61 20 63 70 6c 20 3a 20 57 73 68 53 68 65 6c 6c 2e 52 75 6e } //00 00  uma cpl : WshShell.Run
	condition:
		any of ($a_*)
 
}