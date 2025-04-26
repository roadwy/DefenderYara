
rule Trojan_Win32_ZLoader_AAB_MTB{
	meta:
		description = "Trojan:Win32/ZLoader.AAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {57 50 e8 fd dd ?? ?? 8b 4d ec 83 c4 08 23 45 f0 21 ?? 8b 75 10 0f b6 04 06 30 01 41 8b 45 e8 48 0f 85 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}