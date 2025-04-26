
rule Trojan_Win32_Alureon_gen_P{
	meta:
		description = "Trojan:Win32/Alureon.gen!P,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 5c 06 04 8a d0 32 1d ?? ?? 40 00 c0 e2 40 0a d0 c0 e2 17 2a da 2a d9 88 5c 06 04 40 3b c7 72 df } //1
		$a_03_1 = {be 65 00 00 00 e8 ?? ?? 00 00 83 f8 04 75 07 be 66 00 00 00 eb 0a 83 f8 08 75 05 be 67 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}