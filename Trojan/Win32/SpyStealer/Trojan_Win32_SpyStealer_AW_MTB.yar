
rule Trojan_Win32_SpyStealer_AW_MTB{
	meta:
		description = "Trojan:Win32/SpyStealer.AW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f be 34 10 68 [0-04] 68 [0-04] e8 [0-04] 83 c4 ?? 0f af f0 89 b5 [0-04] 8b 4d ?? 03 4d ?? 8a 11 88 55 ?? 0f be 45 ?? 33 85 [0-04] 8b 4d ?? 03 4d ?? 88 01 eb } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}