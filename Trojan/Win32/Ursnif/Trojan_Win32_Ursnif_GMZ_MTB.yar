
rule Trojan_Win32_Ursnif_GMZ_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.GMZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b c8 33 d1 8b 45 ?? 8b 8d ?? ?? ?? ?? 03 14 81 a1 ?? ?? ?? ?? 03 85 ?? ?? ?? ?? 88 10 0f b6 4d ?? 03 8d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}