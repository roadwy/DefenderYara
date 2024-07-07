
rule Trojan_Win32_Vundo_gen_BR{
	meta:
		description = "Trojan:Win32/Vundo.gen!BR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f 8e e1 00 00 00 89 5d e4 bf 90 01 04 eb 03 8b 75 08 89 5d e0 68 90 01 04 8d 45 a8 89 5d fc e8 e5 03 00 00 90 00 } //2
		$a_00_1 = {37 00 37 00 2e 00 37 00 34 00 2e 00 34 00 38 00 2e 00 31 00 31 00 33 00 00 00 } //1
		$a_01_2 = {44 4e 53 43 68 61 6e 67 65 72 57 69 6e 2e 64 6c 6c 00 72 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}