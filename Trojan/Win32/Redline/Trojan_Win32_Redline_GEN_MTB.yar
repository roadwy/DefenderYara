
rule Trojan_Win32_Redline_GEN_MTB{
	meta:
		description = "Trojan:Win32/Redline.GEN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 d9 03 f9 81 a4 94 ?? ?? ?? ?? 8d 65 01 27 c1 c0 17 89 bc 14 ?? ?? ?? ?? c3 e8 ?? ?? ?? ?? c7 44 24 ?? 14 a6 2e c9 8b 44 25 ?? c7 04 24 } //10
		$a_01_1 = {50 40 2e 65 68 5f 66 72 61 6d } //1 P@.eh_fram
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}