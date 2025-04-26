
rule Trojan_Win32_Heodo_RPG_MTB{
	meta:
		description = "Trojan:Win32/Heodo.RPG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 d2 03 c1 b9 69 09 00 00 f7 f1 8b 4d f4 2b 55 d0 03 55 cc 03 15 ?? ?? ?? ?? 0f b6 04 1a 8b 55 f0 30 04 0a 41 89 4d f4 3b cf b9 69 09 00 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}