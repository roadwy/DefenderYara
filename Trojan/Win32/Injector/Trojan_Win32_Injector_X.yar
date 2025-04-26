
rule Trojan_Win32_Injector_X{
	meta:
		description = "Trojan:Win32/Injector.X,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {74 72 37 71 65 74 37 71 36 77 74 65 37 31 32 37 36 72 38 } //1 tr7qet7q6wte71276r8
		$a_03_1 = {33 db 8d 0c 5d ?? ?? ?? ?? 91 2d [0-10] 3b c2 75 ?? 8d 92 6f 8c ff ff eb ?? 2b 15 ?? ?? ?? ?? 3b c2 76 [0-30] 5d ff e2 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}