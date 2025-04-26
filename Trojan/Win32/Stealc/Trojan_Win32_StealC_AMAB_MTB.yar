
rule Trojan_Win32_StealC_AMAB_MTB{
	meta:
		description = "Trojan:Win32/StealC.AMAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c0 46 89 45 ?? 83 6d ?? ?? ?? 83 6d ?? ?? 8b 45 ?? 8a 4d ?? 03 c6 30 08 46 3b 75 ?? 7c ?? 83 7d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}