
rule Trojan_Win32_SpyStealer_XO_MTB{
	meta:
		description = "Trojan:Win32/SpyStealer.XO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {66 89 4d f8 c7 45 90 01 05 ba 90 01 04 66 89 55 90 01 01 8b 45 90 01 01 35 90 01 04 89 45 90 01 01 c7 45 90 01 05 8b 4d 90 01 01 81 c1 90 01 04 89 4d 90 01 01 c7 45 90 01 05 83 7d 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}