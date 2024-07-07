
rule Trojan_Win32_SpyStealer_AW_MTB{
	meta:
		description = "Trojan:Win32/SpyStealer.AW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f be 34 10 68 90 02 04 68 90 02 04 e8 90 02 04 83 c4 90 01 01 0f af f0 89 b5 90 02 04 8b 4d 90 01 01 03 4d 90 01 01 8a 11 88 55 90 01 01 0f be 45 90 01 01 33 85 90 02 04 8b 4d 90 01 01 03 4d 90 01 01 88 01 eb 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}