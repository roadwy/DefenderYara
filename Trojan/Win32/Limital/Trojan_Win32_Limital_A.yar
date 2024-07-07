
rule Trojan_Win32_Limital_A{
	meta:
		description = "Trojan:Win32/Limital.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f 85 b6 00 00 00 8b 85 90 01 04 3b 46 40 0f 85 a7 00 00 00 8b b5 90 01 04 56 ff 15 90 01 04 85 c0 74 39 56 ff 15 90 01 04 85 c0 75 2e 90 00 } //2
		$a_03_1 = {56 33 c9 8b 45 08 8d 04 48 be 90 01 02 00 00 66 31 30 41 83 f9 32 7c ec 4a 75 e7 90 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}