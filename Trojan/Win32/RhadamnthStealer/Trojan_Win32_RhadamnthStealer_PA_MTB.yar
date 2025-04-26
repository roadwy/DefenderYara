
rule Trojan_Win32_RhadamnthStealer_PA_MTB{
	meta:
		description = "Trojan:Win32/RhadamnthStealer.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {2c 01 88 45 ?? 8b 45 ?? 33 85 [0-04] 0f b6 4d ?? 8b 95 [0-04] 89 04 8a e9 } //1
		$a_03_1 = {2c 01 88 45 ?? 8b 45 ?? 8b 8d [0-04] d3 e0 0f b6 4d ?? 8b 95 [0-04] 89 04 8a e9 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}