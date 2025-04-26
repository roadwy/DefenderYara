
rule Trojan_Win32_Graftor_GPA_MTB{
	meta:
		description = "Trojan:Win32/Graftor.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {83 1c ec 24 6a 01 ff 15 48 20 40 c0 85 c0 0f 7c 76 8d 44 fc 0e 50 68 38 1d 6a 04 de 30 5b 58 13 } //1
		$a_01_1 = {28 38 10 68 10 30 c6 0a 66 c7 34 38 1c 03 6e 0d ee 01 1c 32 5d 3c 2c 4d 08 31 8b f0 69 04 51 9e } //1
		$a_01_2 = {50 40 4d 5e 0e fa 20 33 c0 83 c4 14 24 c3 90 01 00 55 8b ec 6a ff 68 78 a0 5e d0 11 80 64 a1 d0 } //1
		$a_01_3 = {e8 79 a8 fc a1 64 01 7a 0c 4f 59 a5 0d 80 5f 88 72 0e 84 13 22 2a 10 7d 8b 63 7c 1b 89 08 21 1c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}