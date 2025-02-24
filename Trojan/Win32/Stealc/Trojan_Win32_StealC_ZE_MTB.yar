
rule Trojan_Win32_StealC_ZE_MTB{
	meta:
		description = "Trojan:Win32/StealC.ZE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d3 c1 e2 ?? 03 55 ?? 8d 0c 18 33 d1 33 55 ?? 05 ?? ?? ?? ?? 2b fa } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}