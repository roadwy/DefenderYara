
rule Trojan_Win32_Kromebit_A{
	meta:
		description = "Trojan:Win32/Kromebit.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b3 63 52 50 88 5c 24 34 c6 44 24 35 68 c6 44 24 36 72 c6 44 24 37 6f c6 44 24 38 6d c6 44 24 39 65 c6 44 24 3a 2e c6 44 24 3b 65 c6 44 24 3c 78 c6 44 24 3d 65 c6 44 24 3e 00 e8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}