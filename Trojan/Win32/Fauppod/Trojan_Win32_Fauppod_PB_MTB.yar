
rule Trojan_Win32_Fauppod_PB_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c3 8d 50 01 0f b7 ca 89 4c 24 ?? 8b 34 24 66 d1 c6 0f b7 fe 8b 5c 24 ?? 0f b7 14 5d ?? ?? ?? ?? 8d 87 ?? ?? ?? ?? 66 c1 c0 0b 0f b7 c8 33 d1 88 54 1c ?? 89 0c 24 84 d2 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}