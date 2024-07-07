
rule Trojan_Win32_Leivion_A{
	meta:
		description = "Trojan:Win32/Leivion.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c7 44 24 0c 40 00 00 00 c7 44 24 08 00 10 00 00 c7 44 24 04 40 42 0f 00 } //1
		$a_01_1 = {83 c0 04 ff d0 c7 45 f4 00 00 00 00 eb 21 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}