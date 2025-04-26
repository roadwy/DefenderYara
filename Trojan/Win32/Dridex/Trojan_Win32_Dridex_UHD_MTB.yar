
rule Trojan_Win32_Dridex_UHD_MTB{
	meta:
		description = "Trojan:Win32/Dridex.UHD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 f8 88 c2 0f b6 c2 8b 7c 24 10 8a 14 07 8b 44 24 18 8a 34 08 30 f2 8b 44 24 ?? 88 14 08 41 c7 44 24 ?? 00 00 00 00 c7 44 24 20 84 46 b0 4d 8b 44 24 1c 39 c1 89 4c 24 08 89 74 24 04 89 5c 24 0c 0f 85 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}