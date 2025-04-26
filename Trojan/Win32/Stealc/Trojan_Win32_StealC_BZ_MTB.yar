
rule Trojan_Win32_StealC_BZ_MTB{
	meta:
		description = "Trojan:Win32/StealC.BZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c8 8b 45 ?? c1 e8 ?? 89 45 ?? 8b 55 ?? 01 55 ?? 33 f1 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}