
rule Trojan_Win32_Nymaim_BAC_MTB{
	meta:
		description = "Trojan:Win32/Nymaim.BAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {58 23 02 83 ea ?? f8 83 d0 ?? c1 c8 ?? 29 f8 83 c0 ?? 89 c7 c1 c7 ?? 89 03 f8 83 d3 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}