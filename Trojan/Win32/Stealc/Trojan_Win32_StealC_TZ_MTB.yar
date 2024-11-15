
rule Trojan_Win32_StealC_TZ_MTB{
	meta:
		description = "Trojan:Win32/StealC.TZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c7 c1 e8 ?? 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? c1 e7 ?? 03 7d ?? 03 c3 33 f8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}