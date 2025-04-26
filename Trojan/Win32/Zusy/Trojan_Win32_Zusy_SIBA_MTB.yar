
rule Trojan_Win32_Zusy_SIBA_MTB{
	meta:
		description = "Trojan:Win32/Zusy.SIBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b f8 8b f1 2b d2 [0-10] 8a 0f 8a 06 46 90 18 47 80 7d 08 ?? 90 18 88 4d ?? 90 18 0f 84 ?? ?? ?? ?? 8a ca bb ?? ?? ?? ?? [0-10] d3 c3 8a 4d 90 1b 04 [0-10] 02 da [0-10] 32 c3 90 18 42 [0-10] 84 c0 0f 84 ?? ?? ?? ?? 3a c1 0f 84 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}