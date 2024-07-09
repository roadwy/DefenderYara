
rule Trojan_Win32_Duqu_E{
	meta:
		description = "Trojan:Win32/Duqu.E,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 02 06 24 ae 74 07 33 c0 e9 } //1
		$a_03_1 = {66 8b 01 ba ?? ?? ?? ?? 66 33 c2 8b 54 24 08 66 89 02 74 16 57 41 41 66 8b 01 42 42 bf ?? ?? ?? ?? 66 33 c7 66 89 02 75 ec } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}