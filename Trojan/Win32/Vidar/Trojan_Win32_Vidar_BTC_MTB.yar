
rule Trojan_Win32_Vidar_BTC_MTB{
	meta:
		description = "Trojan:Win32/Vidar.BTC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 90 01 01 03 c3 03 ce 31 4c 24 90 01 01 c7 05 90 01 08 c7 05 90 01 08 89 44 24 90 01 01 8b 44 24 90 01 01 31 44 24 90 01 01 8b 44 24 90 01 01 29 44 24 90 01 01 8b 44 24 90 01 01 29 44 24 90 01 01 4f 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}