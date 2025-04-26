
rule Trojan_Win32_Azorult_EZ_MTB{
	meta:
		description = "Trojan:Win32/Azorult.EZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b cf c1 e9 ?? 89 4d ?? 8b 45 ?? 01 45 ?? 8b 55 ?? 8b 45 ?? c1 e7 04 03 7d ?? 03 c2 33 f8 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}