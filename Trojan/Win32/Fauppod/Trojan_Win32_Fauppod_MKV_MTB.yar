
rule Trojan_Win32_Fauppod_MKV_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 f2 89 55 e0 8b 55 e0 89 d0 99 f7 f9 89 15 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 ea ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 8b 55 dc 8b 75 ec 0f b6 14 16 8b 35 ?? ?? ?? ?? 8b 7d e4 0f b6 34 37 31 f2 88 d3 8b 55 dc 8b 75 e8 88 1c 16 8b 45 dc 05 01 00 00 00 89 45 dc e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}