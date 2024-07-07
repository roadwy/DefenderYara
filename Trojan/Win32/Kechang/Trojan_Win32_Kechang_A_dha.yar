
rule Trojan_Win32_Kechang_A_dha{
	meta:
		description = "Trojan:Win32/Kechang.A!dha,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {25 00 73 00 5c 00 54 00 65 00 6d 00 70 00 5c 00 61 00 63 00 72 00 74 00 61 00 79 00 2e 00 65 00 78 00 65 00 } //1 %s\Temp\acrtay.exe
		$a_01_1 = {25 00 73 00 5c 00 74 00 65 00 6d 00 70 00 5c 00 74 00 65 00 6d 00 70 00 65 00 66 00 32 00 } //1 %s\temp\tempef2
		$a_01_2 = {25 00 73 00 5c 00 54 00 65 00 6d 00 70 00 5c 00 64 00 32 00 66 00 6d 00 65 00 2e 00 74 00 6d 00 70 00 } //1 %s\Temp\d2fme.tmp
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}