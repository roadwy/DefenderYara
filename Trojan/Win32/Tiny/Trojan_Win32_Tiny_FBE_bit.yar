
rule Trojan_Win32_Tiny_FBE_bit{
	meta:
		description = "Trojan:Win32/Tiny.FBE!bit,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 1d 00 10 40 00 89 9d f8 07 00 00 a1 a0 30 40 00 89 45 30 a1 9c 30 40 00 89 45 38 } //1
		$a_01_1 = {68 20 4e 00 00 ff 15 a8 30 40 00 6a 04 68 00 30 00 00 68 00 14 00 00 6a 00 ff 15 ac 30 40 00 } //1
		$a_01_2 = {00 ff 55 30 90 89 45 48 90 e8 0f 00 00 00 49 73 57 6f 77 36 34 50 72 6f 63 65 73 73 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}