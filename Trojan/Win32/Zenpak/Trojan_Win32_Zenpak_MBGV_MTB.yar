
rule Trojan_Win32_Zenpak_MBGV_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.MBGV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 7d ec 8a 1c 0f 8b 7d e4 32 1c 37 8b 75 e8 88 1c 0e 8b 35 ?? ?? ?? ?? 81 c6 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 81 c1 01 00 00 00 8b 75 f0 39 f1 8b 75 d0 89 4d e0 89 75 dc 89 55 d8 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}