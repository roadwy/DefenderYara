
rule Trojan_Win32_Injector_BC_MTB{
	meta:
		description = "Trojan:Win32/Injector.BC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {41 21 c9 31 38 89 c9 40 89 ca 81 c1 90 01 04 39 d8 75 e2 90 00 } //02 00 
		$a_03_1 = {47 21 f6 be 90 02 04 29 ce 81 ff 80 66 00 01 75 a6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}