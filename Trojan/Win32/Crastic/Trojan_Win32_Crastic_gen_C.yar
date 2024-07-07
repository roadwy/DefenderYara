
rule Trojan_Win32_Crastic_gen_C{
	meta:
		description = "Trojan:Win32/Crastic.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {ff d7 88 04 33 46 83 fe 40 72 f5 5f 8b 4d fc 33 cd 5e e8 } //1
		$a_01_1 = {63 73 72 73 73 2e 64 6c 6c 00 52 75 6e 64 6c 6c 33 32 4d 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}