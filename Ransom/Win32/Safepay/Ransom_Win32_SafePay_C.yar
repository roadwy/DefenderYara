
rule Ransom_Win32_SafePay_C{
	meta:
		description = "Ransom:Win32/SafePay.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 02 8d 52 01 8b ce c1 e6 08 c1 e9 18 33 c8 0f b6 c1 } //1
		$a_01_1 = {3d 2c 08 00 00 77 1f 74 24 3d 19 08 00 00 77 25 3d 18 08 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}