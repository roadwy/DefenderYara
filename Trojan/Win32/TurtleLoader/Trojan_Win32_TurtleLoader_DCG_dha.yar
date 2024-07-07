
rule Trojan_Win32_TurtleLoader_DCG_dha{
	meta:
		description = "Trojan:Win32/TurtleLoader.DCG!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {e8 6e d8 f8 ff b8 7c ac 47 00 e8 28 dd f8 ff a3 84 ac 47 00 68 74 ac 47 00 6a 40 a1 7c ac 47 } //1
		$a_01_1 = {50 a1 84 ac 47 00 50 e8 0a ff f8 ff a1 84 ac 47 00 a3 88 ac 47 00 ff 15 88 ac 47 00 } //1
		$a_00_2 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 64 61 74 61 2e 62 69 6e } //1 C:\Windows\data.bin
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}