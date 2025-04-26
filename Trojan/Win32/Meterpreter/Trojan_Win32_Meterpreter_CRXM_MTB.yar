
rule Trojan_Win32_Meterpreter_CRXM_MTB{
	meta:
		description = "Trojan:Win32/Meterpreter.CRXM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {fc e8 8f 00 00 00 60 31 d2 64 8b 52 30 89 e5 8b 52 0c 8b 52 14 0f b7 4a 26 8b 72 28 31 } //1
		$a_01_1 = {10 8b 42 3c 01 d0 8b 40 78 85 c0 74 4c 01 d0 8b 58 20 01 d3 50 8b 48 18 85 c9 } //1
		$a_01_2 = {f8 3b 7d 24 75 e0 58 8b 58 24 01 d3 66 8b 0c 4b 8b 58 1c 01 d3 8b 04 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}