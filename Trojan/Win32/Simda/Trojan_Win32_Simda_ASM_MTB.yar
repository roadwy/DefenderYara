
rule Trojan_Win32_Simda_ASM_MTB{
	meta:
		description = "Trojan:Win32/Simda.ASM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {57 be 00 03 3c 00 81 c6 3f 87 05 00 56 bb a3 23 12 00 8b d3 c7 05 ?? ?? ?? ?? e4 63 2f 00 03 15 ?? ?? ?? ?? 52 b9 ae 00 00 00 8b d1 52 68 00 00 00 00 5a 52 bf 88 70 20 00 8b c7 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}