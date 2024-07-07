
rule DDoS_Win32_Nitol_I{
	meta:
		description = "DDoS:Win32/Nitol.I,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {2e c6 84 24 90 01 01 00 00 00 65 c6 84 24 90 01 01 00 00 00 78 c6 84 24 90 01 01 00 00 00 65 c6 84 24 90 01 01 00 00 00 00 90 00 } //1
		$a_03_1 = {8b 55 fc 8a 1c 11 80 f3 90 01 01 88 1c 11 41 3b c8 7c e6 90 00 } //1
		$a_01_2 = {74 00 72 00 30 00 6a 00 34 00 6e 00 } //1 tr0j4n
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}