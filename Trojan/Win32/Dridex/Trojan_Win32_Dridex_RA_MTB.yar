
rule Trojan_Win32_Dridex_RA_MTB{
	meta:
		description = "Trojan:Win32/Dridex.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 5d e8 8b 75 dc 0f b6 34 33 01 fe 8b 7d ec 0f b6 14 17 01 d6 89 35 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 4c 23 00 00 89 f0 99 f7 f9 89 15 ?? ?? ?? ?? 8b 4d dc 8a 0c 0b 88 0d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}