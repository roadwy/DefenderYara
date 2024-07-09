
rule Trojan_Win32_StealC_OPT_MTB{
	meta:
		description = "Trojan:Win32/StealC.OPT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c7 d3 e8 03 45 ?? 89 45 f8 8b 45 ?? 31 45 fc 8b 45 fc 89 45 ?? 89 75 ?? 8b 45 ?? 89 45 ?? 8b 45 f8 31 45 ?? 8b 45 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}