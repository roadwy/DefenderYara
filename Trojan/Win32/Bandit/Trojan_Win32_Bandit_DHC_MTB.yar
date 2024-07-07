
rule Trojan_Win32_Bandit_DHC_MTB{
	meta:
		description = "Trojan:Win32/Bandit.DHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {2b f8 8b 44 24 90 01 01 d1 6c 24 90 01 01 29 44 24 90 01 01 ff 4c 24 90 01 01 0f 85 90 01 04 81 3d 90 01 04 61 01 00 00 5b 75 14 55 55 ff 15 90 01 04 55 55 55 55 55 55 ff 15 90 01 04 8b 44 24 90 01 01 89 38 5f 89 70 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}