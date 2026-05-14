
rule Trojan_Win32_ICLoader_AHB_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 55 e0 81 e2 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 55 e0 8a 45 f0 34 ?? 88 45 f0 eb } //30
		$a_03_1 = {8a 11 c1 fa ?? 8b 45 10 03 45 f8 33 c9 66 8b 48 ?? c1 e1 ?? 0b d1 89 55 c0 eb } //20
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*20) >=50
 
}