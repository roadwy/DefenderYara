
rule Trojan_Win32_Vundo_gen_W{
	meta:
		description = "Trojan:Win32/Vundo.gen!W,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {53 c1 c3 e6 5b 55 0f [0-08] 56 57 2b fd 4f 0b f8 5f 57 0f [0-08] 53 50 57 } //1
		$a_01_1 = {64 8b 40 30 52 c1 ca 3c 42 5a 8b 40 0c 50 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}