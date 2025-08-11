
rule Trojan_Win32_Obfuse_A{
	meta:
		description = "Trojan:Win32/Obfuse.A,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c7 45 d4 6b 65 72 6e c7 45 d8 65 6c 33 32 c7 45 dc 2e 64 6c 6c c6 45 e0 00 } //1
		$a_01_1 = {c7 45 e4 47 65 74 54 c7 45 e8 69 63 6b 43 c7 45 ec 6f 75 6e 74 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}