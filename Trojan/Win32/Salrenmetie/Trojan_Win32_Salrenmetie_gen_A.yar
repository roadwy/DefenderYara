
rule Trojan_Win32_Salrenmetie_gen_A{
	meta:
		description = "Trojan:Win32/Salrenmetie.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 83 c0 08 89 45 fc 8b 4d fc 83 c1 09 89 4d fc 8b 55 fc 83 c2 0a 89 55 fc 68 20 4e 00 00 ff 15 00 10 40 00 6a 00 ff 15 08 10 40 00 33 c0 8b e5 5d c3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}