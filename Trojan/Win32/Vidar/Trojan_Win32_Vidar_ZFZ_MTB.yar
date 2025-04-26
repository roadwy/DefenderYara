
rule Trojan_Win32_Vidar_ZFZ_MTB{
	meta:
		description = "Trojan:Win32/Vidar.ZFZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 c2 03 47 34 69 c0 05 84 08 08 40 89 47 34 c1 e8 18 0f b6 d1 31 c2 c1 e9 08 33 0c 95 ?? ?? ?? ?? 89 4f 38 32 7c 24 03 88 7c 35 00 8b 6c 24 20 46 39 f5 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}