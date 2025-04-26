
rule Trojan_Win32_Simda_RK_MTB{
	meta:
		description = "Trojan:Win32/Simda.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {be 35 24 00 00 6b d6 59 0b 15 ?? ?? ?? ?? 75 05 c1 c2 07 d1 e2 89 15 b7 82 48 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}