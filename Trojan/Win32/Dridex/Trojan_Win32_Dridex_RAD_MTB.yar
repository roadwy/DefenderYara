
rule Trojan_Win32_Dridex_RAD_MTB{
	meta:
		description = "Trojan:Win32/Dridex.RAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {b8 5f 33 00 00 85 c0 74 90 01 01 8b 4d 90 01 01 3b 0d 90 01 04 72 90 01 01 eb 90 01 01 eb 90 01 01 8b 55 90 01 01 03 55 90 01 01 8b 45 90 01 01 03 45 90 01 01 8b 4d 90 01 01 8a 00 88 04 11 8b 4d 90 01 01 83 c1 01 89 4d 90 01 01 eb 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}