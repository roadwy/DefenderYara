
rule Trojan_Win32_Etchfro_C{
	meta:
		description = "Trojan:Win32/Etchfro.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 04 0e 32 01 8a d0 c0 ea 04 c0 e0 04 } //1
		$a_01_1 = {8b ce 8a d0 c0 ea 04 c0 e0 04 0a d0 88 11 8a 41 01 41 84 c0 75 ec } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}