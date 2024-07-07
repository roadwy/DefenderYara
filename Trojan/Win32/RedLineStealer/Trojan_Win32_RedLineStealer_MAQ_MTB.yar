
rule Trojan_Win32_RedLineStealer_MAQ_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.MAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b fe 25 bb 52 c0 5d 8b 45 fc 83 25 90 01 04 00 03 c7 50 8b c7 c1 e0 04 03 45 f0 e8 90 01 04 8b cf c1 e9 05 03 4d e4 33 c1 2b d8 8b 45 ec 29 45 fc ff 4d f4 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}