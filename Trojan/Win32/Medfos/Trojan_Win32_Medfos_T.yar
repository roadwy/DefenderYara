
rule Trojan_Win32_Medfos_T{
	meta:
		description = "Trojan:Win32/Medfos.T,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {60 b8 01 00 00 00 90 05 05 01 90 90 13 0f a2 89 45 ec 89 55 ed } //3
		$a_01_1 = {8a 80 e8 07 00 00 84 c0 5f 5e } //1
		$a_01_2 = {c6 45 fa 78 c6 45 fb 65 c6 45 fc 00 66 ab 33 ff } //1
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}