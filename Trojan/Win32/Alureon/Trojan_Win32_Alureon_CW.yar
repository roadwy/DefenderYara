
rule Trojan_Win32_Alureon_CW{
	meta:
		description = "Trojan:Win32/Alureon.CW,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {76 0f 8a d1 80 c2 ?? 30 14 01 41 3b 4c 24 04 72 f1 } //1
		$a_03_1 = {eb 03 83 c0 28 6a 05 33 d2 59 8b f0 bf ?? ?? ?? ?? f3 a6 75 ed } //1
		$a_01_2 = {55 41 43 64 2e 73 79 73 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}