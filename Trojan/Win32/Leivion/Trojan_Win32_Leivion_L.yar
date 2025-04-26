
rule Trojan_Win32_Leivion_L{
	meta:
		description = "Trojan:Win32/Leivion.L,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 ec c6 00 bf 8b 45 ec 8d 50 01 } //1
		$a_01_1 = {c7 44 24 0c 40 00 00 00 c7 44 24 08 00 10 00 00 89 44 24 04 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}