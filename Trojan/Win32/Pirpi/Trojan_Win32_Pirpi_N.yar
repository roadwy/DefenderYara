
rule Trojan_Win32_Pirpi_N{
	meta:
		description = "Trojan:Win32/Pirpi.N,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {3c 02 74 04 3c 01 75 90 14 80 bc 24 90 01 02 00 00 02 0f 85 90 01 02 00 00 68 60 ea 00 00 ff 15 90 01 04 8d 54 24 90 01 01 52 ff 15 90 00 } //1
		$a_01_1 = {8b 74 24 0c 85 f6 74 19 33 c0 85 f6 7e 13 8a 54 24 10 53 8a 1c 08 32 da 88 1c 08 40 3b c6 7c f3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}