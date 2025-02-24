
rule Trojan_Win32_LummaC_AE_MTB{
	meta:
		description = "Trojan:Win32/LummaC.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 ?? 89 45 ?? 8b 45 ?? 01 45 ?? 8b 4d ?? c1 e6 ?? 03 75 ?? 8d 14 0b 33 f2 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}