
rule Trojan_Win32_Lyinos_A{
	meta:
		description = "Trojan:Win32/Lyinos.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {50 54 6a 00 6a 01 6a 14 e4 ?? 59 85 c0 75 } //1
		$a_01_1 = {ff 30 8f 86 b0 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}