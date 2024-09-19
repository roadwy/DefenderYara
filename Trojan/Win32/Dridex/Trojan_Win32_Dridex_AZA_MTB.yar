
rule Trojan_Win32_Dridex_AZA_MTB{
	meta:
		description = "Trojan:Win32/Dridex.AZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 74 24 40 32 16 8b 74 24 18 88 14 0e 03 44 24 3c 8b 4c 24 38 89 4c 24 64 89 44 24 ?? 8b 4c 24 34 89 4c 24 44 8b 4c 24 30 39 c8 74 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}