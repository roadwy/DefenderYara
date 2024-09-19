
rule Trojan_Win32_Korplug_GMN_MTB{
	meta:
		description = "Trojan:Win32/Korplug.GMN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b e8 8b 4d ?? 8d 41 ?? 89 45 ?? 8a 44 9c ?? 8b 9c 24 ?? ?? ?? ?? 32 04 1a 88 44 29 ?? 8d 44 24 ?? 50 6a 01 52 e8 ?? ?? ?? ?? 83 c4 ?? 84 c0 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}