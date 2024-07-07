
rule Ransom_Win32_Urausy_A{
	meta:
		description = "Ransom:Win32/Urausy.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {58 87 04 24 8b 04 03 21 c0 74 10 8b 10 80 fa cc 74 09 66 81 fa eb fe 74 02 ff e0 } //1
		$a_03_1 = {b9 06 00 00 00 f3 ab c7 85 90 01 02 ff ff 18 00 00 00 c7 85 90 01 02 ff ff 40 00 00 00 8d 8d 90 01 02 ff ff 8d 95 90 01 02 ff ff 8d 45 f8 51 52 6a 3a 50 68 90 01 02 00 00 e8 90 01 04 09 c0 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}