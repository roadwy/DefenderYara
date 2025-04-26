
rule Trojan_Win32_Diple_B_bit{
	meta:
		description = "Trojan:Win32/Diple.B!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {8b cf 8b c7 c1 e9 05 03 4d f8 c1 e0 04 03 45 f4 33 c8 8d } //1
		$a_01_1 = {04 3b 33 c8 2b f1 8b ce 8b c6 c1 e9 05 03 4d f0 c1 e0 04 03 45 ec 33 c8 8d 04 33 33 c8 8d 9b 47 86 c8 61 2b f9 83 6d 0c 01 75 b4 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}