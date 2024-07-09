
rule Trojan_Win32_Alureon_gen_I{
	meta:
		description = "Trojan:Win32/Alureon.gen!I,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {76 21 8a 44 24 10 53 56 8b 74 24 10 8a 1c 31 8a d1 02 d0 32 da 88 1c 31 41 3b cf 72 ef 8b c6 } //1
		$a_03_1 = {3d 00 00 00 80 73 15 68 ?? ?? 40 00 68 ?? ?? 40 00 e8 ?? ?? ff ff 85 c0 75 38 eb 2f 68 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}