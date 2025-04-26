
rule Trojan_Win32_Danmec_gen_C{
	meta:
		description = "Trojan:Win32/Danmec.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {3c 0d 74 10 3c 0a 75 06 c6 04 1e 00 eb 05 34 1b 88 04 1e 46 ?? 3b [0-03] 72 } //1
		$a_01_1 = {3c 0d 74 27 6a 09 33 c9 5b 8a 54 0d f4 49 3a 54 0d e9 75 04 88 54 0d e1 4b 75 ee 3c 0a 75 06 c6 04 3e 00 eb 05 34 1b 88 04 3e 46 8b 4d f8 41 3b 4d 0c 89 4d f8 72 b3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}