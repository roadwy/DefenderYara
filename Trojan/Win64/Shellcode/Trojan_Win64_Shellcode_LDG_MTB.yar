
rule Trojan_Win64_Shellcode_LDG_MTB{
	meta:
		description = "Trojan:Win64/Shellcode.LDG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 8b c8 b8 ?? ?? ?? ?? 41 f7 e0 41 8b c0 41 ff c0 2b c2 d1 e8 03 c2 c1 e8 ?? 6b c0 ?? 2b c8 8a 4c 0d ?? 32 0b 48 ff c3 41 88 09 49 ff c1 44 3b c6 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}