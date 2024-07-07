
rule Trojan_Win32_InfoStealer_VD_MTB{
	meta:
		description = "Trojan:Win32/InfoStealer.VD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f3 0f 10 c9 f3 0f 10 f6 f3 0f 10 f6 f3 0f 10 f6 90 02 15 33 94 85 90 01 04 88 16 f3 0f 10 d2 f3 0f 10 c0 f3 0f 10 c0 f3 0f 10 ff 46 90 02 15 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_InfoStealer_VD_MTB_2{
	meta:
		description = "Trojan:Win32/InfoStealer.VD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 74 93 10 8b 14 93 d3 c6 8b 4d 08 03 f0 c1 e9 1b d3 c2 8b 4d 08 8b c1 c1 e8 05 03 d0 8b 45 fc 33 f2 8b 55 f8 03 c2 33 f0 03 75 ec 83 6d f4 01 89 4d ec 8b cf 89 75 fc 8b fe 89 4d 08 0f 85 66 ff ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}