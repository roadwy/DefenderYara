
rule Trojan_Win32_Emotet_CCFJ_MTB{
	meta:
		description = "Trojan:Win32/Emotet.CCFJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 c8 8b 40 ?? 89 45 ?? 8b 45 ?? c1 e0 ?? 03 45 ?? 0f b7 40 ?? 89 45 ?? 8b 45 ?? 33 45 ?? 89 45 ?? 8b 45 ?? 03 45 ?? 89 45 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}