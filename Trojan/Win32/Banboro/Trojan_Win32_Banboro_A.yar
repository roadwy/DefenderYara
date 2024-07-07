
rule Trojan_Win32_Banboro_A{
	meta:
		description = "Trojan:Win32/Banboro.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {42 52 42 20 42 61 6e 6b 6e 65 74 20 96 20 42 61 6e 63 6f 20 64 65 20 42 72 61 73 ed 6c 69 61 } //1
		$a_01_1 = {34 44 36 46 37 41 36 39 36 43 36 43 36 31 32 30 34 36 36 39 37 32 36 35 36 36 36 46 37 38 } //1 4D6F7A696C6C612046697265666F78
		$a_01_2 = {47 65 72 65 6e 63 69 61 64 6f 72 20 64 65 20 54 61 72 65 66 61 73 20 64 6f 20 57 69 6e 64 6f 77 73 } //1 Gerenciador de Tarefas do Windows
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}