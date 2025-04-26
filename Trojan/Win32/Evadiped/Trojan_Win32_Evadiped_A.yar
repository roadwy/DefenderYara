
rule Trojan_Win32_Evadiped_A{
	meta:
		description = "Trojan:Win32/Evadiped.A,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {99 f7 f9 8b 44 24 1c 83 c6 01 8a 14 02 8a 44 3e ff 8a da f6 d3 22 d8 f6 d0 22 c2 0a d8 3b f5 88 5c 3e ff 7c d9 } //10
		$a_01_1 = {41 30 45 31 30 35 34 42 2d } //1 A0E1054B-
		$a_01_2 = {23 32 30 36 00 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=11
 
}