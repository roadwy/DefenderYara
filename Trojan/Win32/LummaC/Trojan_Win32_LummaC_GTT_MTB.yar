
rule Trojan_Win32_LummaC_GTT_MTB{
	meta:
		description = "Trojan:Win32/LummaC.GTT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {21 d6 09 ca f7 d2 09 f2 89 d6 81 f6 ?? ?? ?? ?? 83 e2 ?? 01 d2 29 f2 88 10 40 49 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_LummaC_GTT_MTB_2{
	meta:
		description = "Trojan:Win32/LummaC.GTT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {21 f1 89 c7 83 f7 ?? 81 e7 ?? ?? ?? ?? 21 f0 09 ca 09 c7 31 fa 89 55 ?? 8b 45 ?? 8b 4d ?? 31 e9 89 45 } //10
		$a_01_1 = {50 72 6f 63 65 73 73 20 48 6f 6c 6c 6f 77 69 6e 67 2e 65 78 65 } //1 Process Hollowing.exe
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}