
rule Trojan_Win32_Obfuscator_DL_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.DL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 e0 04 03 44 24 20 8b ce c1 e9 05 03 d6 33 c2 03 cf 81 3d 34 c5 c5 02 ?? ?? ?? ?? c7 05 b8 c3 c5 02 ?? ?? ?? ?? 89 2d b0 c3 c5 02 89 2d b4 c3 c5 02 89 44 24 10 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}