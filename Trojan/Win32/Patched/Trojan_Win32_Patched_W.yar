
rule Trojan_Win32_Patched_W{
	meta:
		description = "Trojan:Win32/Patched.W,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a c1 8a d1 f6 e9 80 f2 01 80 e2 07 32 c2 8a 14 31 32 d0 88 14 31 41 3b cf 72 e5 } //1
		$a_03_1 = {68 89 fd 12 a4 56 89 75 ec e8 ?? ?? ?? ?? 68 19 d0 d6 02 56 8b f8 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}