
rule Trojan_Win32_RaccoonStealer_DA_MTB{
	meta:
		description = "Trojan:Win32/RaccoonStealer.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d5 c1 ea 05 c7 05 90 01 04 84 10 d6 cb c7 05 90 01 04 ff ff ff ff 89 54 24 90 01 01 8b 84 24 90 01 04 01 44 24 90 01 01 8b 44 24 90 01 01 33 c7 33 c6 2b d8 81 3d 90 01 04 17 04 00 00 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}