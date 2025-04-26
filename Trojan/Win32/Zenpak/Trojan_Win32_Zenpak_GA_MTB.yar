
rule Trojan_Win32_Zenpak_GA_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 c0 8a 44 34 ?? 81 e1 ?? ?? ?? ?? 03 c1 83 c4 ?? 25 [0-30] 48 0d ?? ?? ?? ?? 40 8a 54 04 ?? 8a 03 32 c2 88 03 43 4d } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}