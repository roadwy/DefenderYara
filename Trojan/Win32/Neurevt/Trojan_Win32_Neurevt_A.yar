
rule Trojan_Win32_Neurevt_A{
	meta:
		description = "Trojan:Win32/Neurevt.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {60 b8 11 11 11 11 c6 00 40 c6 40 01 41 c6 40 02 42 c6 40 03 43 c6 40 04 44 c6 40 05 45 c6 40 06 46 33 c0 50 50 50 68 22 22 22 22 50 50 b8 33 33 33 33 ff d0 } //1
		$a_01_1 = {25 64 7c 25 73 7c 25 73 7c 25 73 } //1 %d|%s|%s|%s
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}