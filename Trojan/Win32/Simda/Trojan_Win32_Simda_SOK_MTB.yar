
rule Trojan_Win32_Simda_SOK_MTB{
	meta:
		description = "Trojan:Win32/Simda.SOK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff 15 bc 20 41 00 33 c0 a3 ?? ?? ?? 00 ba 41 0c 00 00 c1 ea 06 03 d3 4a 8b c2 40 81 e8 f0 04 00 00 2b ?? ?? ?? 40 00 c1 c0 07 03 c0 29 05 ?? ?? ?? 00 68 1f a2 40 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}