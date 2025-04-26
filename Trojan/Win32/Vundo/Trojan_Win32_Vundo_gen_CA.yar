
rule Trojan_Win32_Vundo_gen_CA{
	meta:
		description = "Trojan:Win32/Vundo.gen!CA,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {ff 14 8d e0 a4 01 10 90 09 0e 00 74 09 8b 45 fc 83 c0 06 89 45 fc 8b 4d fc } //1
		$a_03_1 = {ff 14 8d 60 52 01 10 90 09 0e 00 74 09 8b 45 fc 83 c0 06 89 45 fc 8b 4d fc } //1
		$a_03_2 = {ff 14 85 00 b0 01 10 90 09 09 00 74 04 83 45 fc 06 8b 45 fc } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}