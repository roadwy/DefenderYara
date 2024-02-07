
rule Trojan_Win32_Dridex_E_MTB{
	meta:
		description = "Trojan:Win32/Dridex.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 03 00 "
		
	strings :
		$a_81_0 = {40 65 63 68 6f 20 6f 66 66 } //03 00  @echo off
		$a_81_1 = {64 65 6c 20 2f 46 20 2f 51 20 2f 41 } //03 00  del /F /Q /A
		$a_81_2 = {48 54 54 50 2f 31 2e 30 } //03 00  HTTP/1.0
		$a_81_3 = {41 4d 36 7a 69 4f 62 41 6b 6b 56 48 74 72 76 5a 46 7a 69 65 6a 61 68 58 } //03 00  AM6ziObAkkVHtrvZFziejahX
		$a_81_4 = {76 43 6c 7a 34 6e 5a 75 62 4e 55 38 64 5a 6c 4b } //03 00  vClz4nZubNU8dZlK
		$a_81_5 = {56 36 62 64 6c 4d 47 79 4e 33 35 59 56 } //00 00  V6bdlMGyN35YV
	condition:
		any of ($a_*)
 
}