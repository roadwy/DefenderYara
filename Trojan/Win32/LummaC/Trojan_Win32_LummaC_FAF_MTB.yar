
rule Trojan_Win32_LummaC_FAF_MTB{
	meta:
		description = "Trojan:Win32/LummaC.FAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {87 c2 41 c1 cb 12 87 c1 2b f2 33 de f7 d6 21 05 ?? ?? ?? ?? 87 c3 f7 de 87 d6 c1 c8 1c 87 f3 f7 d1 41 } //3
	condition:
		((#a_03_0  & 1)*3) >=3
 
}