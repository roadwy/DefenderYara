
rule Trojan_Win32_Fragtor_GNQ_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.GNQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 84 11 ?? ?? ?? ?? 33 f6 8b 55 ?? c1 e0 ?? 89 45 ?? 8b d8 0f b6 04 37 6a 04 8a 84 18 ?? ?? ?? ?? 30 04 32 46 58 3b f0 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}