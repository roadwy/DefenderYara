
rule Trojan_Win32_Coinminer_CCJT_MTB{
	meta:
		description = "Trojan:Win32/Coinminer.CCJT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {74 00 61 00 c7 45 ?? 6e 00 74 00 c7 45 ?? 54 00 4e 00 c7 45 ?? 51 00 30 00 c7 45 ?? 4e 00 32 00 c7 45 ?? 54 00 61 00 c7 45 ?? 51 00 75 00 c7 45 ?? 31 00 71 00 c7 45 ?? 54 00 4e 00 c7 45 ?? 51 00 30 00 c7 45 ?? 4e 00 32 00 c7 45 ?? 54 00 61 00 c7 45 ?? 51 00 75 00 c7 45 ?? 31 00 70 00 c7 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}