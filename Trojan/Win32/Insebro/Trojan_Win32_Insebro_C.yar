
rule Trojan_Win32_Insebro_C{
	meta:
		description = "Trojan:Win32/Insebro.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {59 74 47 a1 90 01 04 66 c7 45 90 01 01 01 00 85 c0 66 c7 45 90 01 01 08 00 75 05 a1 90 01 04 50 ff d7 90 00 } //2
		$a_01_1 = {72 65 73 3a 2f 2f 69 65 6f 63 78 2e 64 6c 6c 2f } //1 res://ieocx.dll/
		$a_01_2 = {72 65 73 3a 2f 2f 69 65 68 6f 73 74 63 78 33 32 2e 64 6c 6c 2f } //1 res://iehostcx32.dll/
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}