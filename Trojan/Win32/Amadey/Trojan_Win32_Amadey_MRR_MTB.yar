
rule Trojan_Win32_Amadey_MRR_MTB{
	meta:
		description = "Trojan:Win32/Amadey.MRR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 d3 e8 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 31 45 ?? 89 3d ?? ?? ?? ?? 8b 45 ?? 29 45 ?? 8b 45 ?? 29 45 ?? ff 4d ?? 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}