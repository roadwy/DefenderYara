
rule Trojan_Win32_Miep_A{
	meta:
		description = "Trojan:Win32/Miep.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6a 07 5f f7 ff 8a 44 15 ec 32 04 31 41 } //1
		$a_01_1 = {80 78 fe 65 75 1b 80 78 fd 78 75 15 80 78 fc 65 } //1
		$a_03_2 = {6a 1a 5e f7 fe a1 90 02 04 80 c2 61 88 54 08 07 a1 90 02 04 88 54 08 07 41 83 f9 04 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}