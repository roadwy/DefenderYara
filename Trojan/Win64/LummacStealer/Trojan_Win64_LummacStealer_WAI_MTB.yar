
rule Trojan_Win64_LummacStealer_WAI_MTB{
	meta:
		description = "Trojan:Win64/LummacStealer.WAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 04 01 48 63 4d ?? 48 8b 55 ?? 30 04 0a 8b 45 ?? 83 c0 ?? 89 45 ?? 8b 05 ?? ?? ?? ?? 8d 48 ?? 0f af c8 f6 c1 ?? b8 ?? ?? ?? ?? b9 ?? ?? ?? ?? e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}