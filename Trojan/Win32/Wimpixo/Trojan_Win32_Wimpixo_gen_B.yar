
rule Trojan_Win32_Wimpixo_gen_B{
	meta:
		description = "Trojan:Win32/Wimpixo.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {81 3a f9 d7 90 90 eb 75 0c 8b 45 90 01 01 81 78 04 2e bb 09 d7 90 00 } //1
		$a_01_1 = {68 67 e0 22 00 8b 45 08 50 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}